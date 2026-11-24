"""Windows x64 kernel address space over a physical memory image, typed through the kernel's PDB or ISF.

Locating the kernel (:func:`locate`), most specific source first:

1. ``--dtb`` / ``--kernel-base`` given by the analyst.
2. Facts the image format records: a crash dump's DirectoryTableBase and PsLoadedModuleList (the first entry of
   that list is ntoskrnl, ``_KLDR_DATA_TABLE_ENTRY.DllBase`` at +0x30 on every x64 build), or the CR3 a
   hibernation file / ELF core / VMware snapshot recorded for a CPU.
3. The x64 "low stub": ``_PROCESSOR_START_BLOCK`` in the first MiB of RAM starts with the bytes ``E9 .. .. 00 01
   00 06 00`` (``q & 0xFFFFFFFFFFFF00FF == 0x00000001000600E9``), holds the kernel CR3 at +0xA0 and a kernel
   entry address (``LmTarget``) at +0x70 (the test MemProcFS uses, ``vmmwininit.c``).
4. A page whose upper-half PML4 entry maps the page itself (Windows' self-referencing PML4 entry).

A DTB candidate is accepted only when it maps ``KUSER_SHARED_DATA`` (0xFFFFF78000000000) with NtMajorVersion 10
(offset 0x26C) and an NtSystemRoot (offset 0x30) that reads as a path (layout per the ``_KUSER_SHARED_DATA`` type,
stable since Windows 2000 for these fields). The kernel base is the page whose PE CodeView record names a kernel
PDB; it is found from the module list, by scanning down from a kernel address, or by scanning the mapped kernel
image range.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.framework.layers import DataLayer
from keto.winmem import pe as pe_mod
from keto.winmem.paging import ADDR, PAGE, PageFault, X64Paging
from keto.winmem.symtab import ARRAY, BASE, BITFIELD, ENUM, POINTER, STRUCT, UNION, SymbolError, SymbolTable, Type

KERNEL_PDBS = ("ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb")
KUSER_SHARED_DATA = 0xFFFFF78000000000
KERNEL_IMAGE_RANGE = (0xFFFFF80000000000, 0xFFFFF88000000000)
LOW_STUB_MAX = 0x100000


def is_kernel_va(va: int) -> bool:
    return va >= 0xFFFF800000000000


class WinKernel:
    """Kernel virtual memory (and, with a process DTB, a process's memory) plus typed access."""

    def __init__(self, phys: DataLayer, dtb: int, base: int, symtab: SymbolTable, levels: int = 4,
                 notes: Optional[List[str]] = None, image_meta: Optional[dict] = None):
        self.phys, self.dtb, self.base, self.symtab, self.levels = phys, dtb & ADDR, base, symtab, levels
        self.notes = notes or []
        self.image_meta = image_meta or {}
        self.paging = X64Paging(self.phys.read, levels)
        self._tlb: Dict[Tuple[int, int], int] = {}
        self._type_names: Dict[int, str] = {}

    # -- translation -----------------------------------------------------------------------------------
    def v2p(self, va: int, dtb: Optional[int] = None) -> int:
        dtb = self.dtb if dtb is None else dtb & ADDR
        key = (dtb, va >> 12)
        page = self._tlb.get(key)
        if page is None:
            pa, _size, _e = self.paging.translate(dtb, va)
            page = pa & ~0xFFF
            if len(self._tlb) > 1 << 16:
                self._tlb.clear()
            self._tlb[key] = page
        return page | (va & 0xFFF)

    def read(self, va: int, n: int, dtb: Optional[int] = None) -> bytes:
        out = bytearray()
        while n > 0:
            take = min(n, PAGE - (va & 0xFFF))
            out += self.phys.read(self.v2p(va, dtb), take)
            va += take
            n -= take
        return bytes(out)

    def readable(self, va: int, dtb: Optional[int] = None) -> bool:
        try:
            self.v2p(va, dtb)
            return True
        except InvalidAddressException:
            return False

    def u8(self, va, dtb=None):
        return self.read(va, 1, dtb)[0]

    def u16(self, va, dtb=None):
        return struct.unpack("<H", self.read(va, 2, dtb))[0]

    def u32(self, va, dtb=None):
        return struct.unpack("<I", self.read(va, 4, dtb))[0]

    def u64(self, va, dtb=None):
        return struct.unpack("<Q", self.read(va, 8, dtb))[0]

    # -- symbols / types ------------------------------------------------------------------------------------
    def has_sym(self, name: str) -> bool:
        return name in self.symtab.symbols

    def sym(self, name: str) -> int:
        try:
            return self.base + self.symtab.rva(name)
        except SymbolError as e:
            raise RequirementError(str(e))

    def obj(self, type_name: str, va: int, dtb: Optional[int] = None) -> "WinObj":
        return WinObj(self, self.symtab.struct(type_name), va, dtb)

    def value(self, t: Type, va: int, dtb: Optional[int] = None):
        if t is None:
            return None
        if t.kind == BITFIELD:
            storage = self.symtab.resolve(t.target)
            size = (storage.size if storage is not None else 0) or 4
            word = int.from_bytes(self.read(va, size, dtb), "little")
            return (word >> t.bit_pos) & ((1 << t.bit_len) - 1)
        if t.kind in (BASE, ENUM, POINTER):
            if not t.size:
                return None
            return int.from_bytes(self.read(va, t.size, dtb), "little", signed=t.kind != POINTER and t.signed)
        if t.kind in (STRUCT, UNION):
            return WinObj(self, t, va, dtb)
        if t.kind == ARRAY:
            return self.read(va, t.size, dtb)
        return None

    def unicode(self, va: int, dtb: Optional[int] = None, limit: int = 0x2000) -> str:
        """The text of a ``_UNICODE_STRING`` at ``va`` (Length u16, MaximumLength u16, Buffer at +8)."""
        length = self.u16(va, dtb)
        buf = self.u64(va + 8, dtb)
        if not length or not buf:
            return ""
        return self.read(buf, min(length, limit) & ~1, dtb).decode("utf-16-le", "replace")

    def list_entries(self, head_va: int, link_off: int, limit: int = 1 << 16,
                     dtb: Optional[int] = None) -> Iterator[int]:
        """Addresses of the structures on a ``_LIST_ENTRY`` list (container_of: entry - ``link_off``); stops on
        a loop, a non-kernel pointer or an unreadable link (reported through :attr:`walk_errors`)."""
        node = self.u64(head_va, dtb)
        seen = set()
        while node and node != head_va and len(seen) < limit:
            if node in seen:
                self.notes.append("list at 0x%x loops back to 0x%x" % (head_va, node))
                return
            seen.add(node)
            yield node - link_off
            try:
                node = self.u64(node, dtb)
            except InvalidAddressException as e:
                self.notes.append("list at 0x%x: link 0x%x unreadable (%s)" % (head_va, node, e))
                return


class WinObj:
    """A typed structure instance at ``va``; members read lazily by path."""

    __slots__ = ("k", "t", "va", "dtb")

    def __init__(self, k: WinKernel, t: Type, va: int, dtb: Optional[int] = None):
        self.k, self.t, self.va, self.dtb = k, t, va, dtb

    def offset(self, path: str) -> int:
        return self.k.symtab.member(self.t, path)[0]

    def has(self, path: str) -> bool:
        return self.k.symtab.has_member(self.t, path)

    def field(self, path: str):
        off, ft = self.k.symtab.member(self.t, path)
        return self.k.value(ft, self.va + off, self.dtb)

    __getitem__ = field

    def get(self, path: str, default=None):
        """``field(path)``, or ``default`` when the member does not exist in this build or is unreadable."""
        try:
            return self.field(path)
        except (SymbolError, InvalidAddressException):
            return default

    def addr(self, path: str) -> int:
        return self.va + self.offset(path)

    def string(self, path: str) -> str:
        data = self.field(path)
        return data.split(b"\x00", 1)[0].decode("latin-1", "replace") if isinstance(data, bytes) else ""

    def unicode(self, path: str) -> str:
        return self.k.unicode(self.addr(path), self.dtb)

    def deref(self, path: str, type_name: Optional[str] = None) -> Optional["WinObj"]:
        off, ft = self.k.symtab.member(self.t, path)
        ptr = self.k.value(ft, self.va + off, self.dtb)
        if not ptr:
            return None
        t = self.k.symtab.struct(type_name) if type_name else self.k.symtab.resolve(ft.target)
        if t is None or t.kind not in (STRUCT, UNION):
            raise SymbolError("%s.%s does not point to a structure" % (self.t.name, path))
        return WinObj(self.k, t, ptr, self.dtb)

    def __repr__(self):
        return "<%s @0x%x>" % (self.t.name, self.va)


# -- locating the kernel --------------------------------------------------------------------------------------
class Located(NamedTuple):
    dtb: int
    base: int
    codeview: pe_mod.CodeView
    levels: int
    notes: List[str]


def kuser_ok(paging: X64Paging, phys: DataLayer, dtb: int) -> Optional[str]:
    """NtSystemRoot when ``dtb`` maps KUSER_SHARED_DATA with a Windows 10/11 version, else None."""
    try:
        pa, _s, _e = paging.translate(dtb, KUSER_SHARED_DATA)
        page = phys.read(pa & ~0xFFF, PAGE)
    except InvalidAddressException:
        return None
    major, minor = struct.unpack_from("<II", page, 0x26C)
    root = page[0x30:0x30 + 520].decode("utf-16-le", "replace").split("\x00", 1)[0]
    if major != 10 or minor != 0 or len(root) < 3 or root[1:3] != ":\\":
        return None
    return root


def find_low_stub(phys: DataLayer) -> Optional[Tuple[int, int]]:
    """``(cr3, LmTarget)`` from ``_PROCESSOR_START_BLOCK`` in the first MiB, if present."""
    for pa in range(0x1000, LOW_STUB_MAX, PAGE):
        try:
            page = phys.read(pa, 0x100)
        except InvalidAddressException:
            continue
        q0, = struct.unpack_from("<Q", page, 0)
        if q0 & 0xFFFFFFFFFFFF00FF != 0x00000001000600E9:
            continue
        lm, = struct.unpack_from("<Q", page, 0x70)
        cr3, = struct.unpack_from("<Q", page, 0xA0)
        if lm & 0xFFFFF80000000003 == 0xFFFFF80000000000 and not cr3 & 0xFFFFFF0000000FFF:
            return cr3, lm
    return None


def self_ref_candidates(phys: DataLayer, limit: int = 64) -> Iterator[int]:
    """Pages with an upper-half entry whose address bits point at the page itself (bytes 2..5 of an 8-byte
    entry hold PA bits 16..47), checked by a byte search before any decoding."""
    found = 0
    for start, length in phys.ranges():
        pa = (start + 0xFFF) & ~0xFFF
        while pa + PAGE <= start + length:
            try:
                page = phys.read(pa, PAGE)
            except InvalidAddressException:
                pa += PAGE
                continue
            needle = struct.pack("<I", (pa >> 16) & 0xFFFFFFFF)
            pos = page.find(needle, 0x800)
            while pos >= 0:
                if (pos - 2) % 8 == 0:
                    e, = struct.unpack_from("<Q", page, pos - 2)
                    if e & 1 and e & ADDR == pa:
                        yield pa
                        found += 1
                        if found >= limit:
                            return
                        break
                pos = page.find(needle, pos + 1)
            pa += PAGE


def _kernel_cv(read_va, base: int) -> Optional[pe_mod.CodeView]:
    cv = pe_mod.safe_codeview(read_va, base)
    if cv is not None and cv.pdb_name.lower() in KERNEL_PDBS:
        return cv
    return None


def find_kernel_base(paging: X64Paging, phys: DataLayer, dtb: int, module_list: Optional[int] = None,
                     hints: Tuple[int, ...] = (), notes: Optional[List[str]] = None
                     ) -> Optional[Tuple[int, pe_mod.CodeView]]:
    notes = notes if notes is not None else []

    def read_va(va, n):
        out = bytearray()
        while n > 0:
            take = min(n, PAGE - (va & 0xFFF))
            pa, _s, _e = paging.translate(dtb, va)
            out += phys.read(pa, take)
            va += take
            n -= take
        return bytes(out)

    if module_list:
        try:
            first = struct.unpack("<Q", read_va(module_list, 8))[0]
            base = struct.unpack("<Q", read_va(first + 0x30, 8))[0]
            cv = _kernel_cv(read_va, base)
            if cv:
                notes.append("kernel base 0x%x from the first PsLoadedModuleList entry" % base)
                return base, cv
        except (InvalidAddressException, struct.error):
            notes.append("PsLoadedModuleList 0x%x recorded by the image is unreadable" % module_list)
    for hint in hints:
        va = hint & ~0xFFF
        for _ in range(0x4000):  # 64 MiB down
            try:
                if read_va(va, 2) == b"MZ":
                    cv = _kernel_cv(read_va, va)
                    if cv:
                        notes.append("kernel base 0x%x found below kernel address 0x%x" % (va, hint))
                        return va, cv
            except InvalidAddressException:
                pass
            va -= PAGE
    for va, pa, size, _e in paging.mappings(dtb, *KERNEL_IMAGE_RANGE):
        for off in range(0, size, PAGE):
            try:
                if phys.read(pa + off, 2) != b"MZ":
                    continue
            except InvalidAddressException:
                continue
            cv = _kernel_cv(read_va, va + off)
            if cv:
                notes.append("kernel base 0x%x found by scanning the kernel image range" % (va + off))
                return va + off, cv
    return None


def _meta_dtbs(meta: dict) -> List[Tuple[int, str]]:
    out = []
    if meta.get("directory_table_base"):
        out.append((int(meta["directory_table_base"]), "%s header DirectoryTableBase" % meta.get("format", "image")))
    cr3 = meta.get("cr3")
    for i, v in enumerate(cr3 if isinstance(cr3, list) else [cr3] if cr3 else []):
        out.append((int(v), "CR3 of CPU %d recorded in the %s" % (i, meta.get("format", "image"))))
    return out


def locate(phys: DataLayer, meta: Optional[dict] = None, dtb: Optional[int] = None,
           kernel_base: Optional[int] = None) -> Located:
    meta = meta or {}
    notes: List[str] = []
    stub = None
    candidates: List[Tuple[int, str]] = []
    if dtb is not None:
        candidates.append((dtb, "--dtb"))
    candidates += _meta_dtbs(meta)
    if not candidates:
        stub = find_low_stub(phys)
        if stub:
            candidates.append((stub[0], "low stub (_PROCESSOR_START_BLOCK) CR3"))
    tried = []
    for levels in (4, 5):
        paging = X64Paging(phys.read, levels)
        pool = list(candidates)
        if not pool and levels == 4:
            pool = [(c, "self-referencing PML4 page") for c in self_ref_candidates(phys)]
        for cand, why in pool:
            root = kuser_ok(paging, phys, cand)
            tried.append("0x%x (%s, %d-level)%s" % (cand, why, levels, "" if root else ": no KUSER_SHARED_DATA"))
            if root is None:
                continue
            notes.append("DTB 0x%x from %s, %d-level paging; KUSER_SHARED_DATA NtSystemRoot %s" % (
                cand & ADDR, why, levels, root))
            hints = tuple(h for h in ((stub[1],) if stub else ()) +
                          tuple(int(meta[k]) for k in ("ps_active_process_head", "kd_debugger_data_block")
                                if meta.get(k)))
            if kernel_base is not None:
                read = lambda va, n, p=paging, c=cand: _read(p, phys, c, va, n)  # noqa: E731
                cv = pe_mod.safe_codeview(read, kernel_base)
                if cv is None:
                    raise RequirementError("--kernel-base 0x%x has no readable PE CodeView record" % kernel_base)
                notes.append("kernel base 0x%x from --kernel-base" % kernel_base)
                return Located(cand & ADDR, kernel_base, cv, levels, notes)
            found = find_kernel_base(paging, phys, cand, meta.get("ps_loaded_module_list"), hints, notes)
            if found:
                return Located(cand & ADDR, found[0], found[1], levels, notes)
            notes.append("no ntoskrnl PE image found under DTB 0x%x" % cand)
        if candidates:
            continue
    raise RequirementError("could not locate a Windows x64 kernel in this image (DTB candidates: %s). Give --dtb "
                           "and --kernel-base if you know them" % ("; ".join(tried) or "none found"))


def _read(paging: X64Paging, phys: DataLayer, dtb: int, va: int, n: int) -> bytes:
    out = bytearray()
    while n > 0:
        take = min(n, PAGE - (va & 0xFFF))
        pa, _s, _e = paging.translate(dtb, va)
        out += phys.read(pa, take)
        va += take
        n -= take
    return bytes(out)


def locate_codeview(ctx) -> pe_mod.CodeView:
    from keto.winmem.session import physical_layer
    layer, _name, meta = physical_layer(ctx)
    return locate(layer, meta).codeview
