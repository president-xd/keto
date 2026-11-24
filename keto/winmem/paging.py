"""x86-64 address translation as Windows uses it, over a physical-memory layer.

Hardware rules (Intel SDM vol. 3A, 4.5): 4-level (PML4) or 5-level (LA57) tables of 512 eight-byte entries;
bit 0 Present, bit 7 PS (1 GiB page at the PDPT, 2 MiB page at the PD), address bits 51:12. CR3 bits 11:0 may
hold a PCID and are ignored.

Windows software PTE states for an entry with Present = 0 (Windows Internals 7th ed., ch. 5 "Page table
entries"; the ``_MMPTE_*`` types in the kernel PDB): bit 11 Transition with bit 10 Prototype clear means the
page is still in RAM on the standby or modified list and the PFN field is valid, so the address is readable;
bit 10 Prototype means the PTE refers to a prototype PTE of a shared section (resolved only with the VAD,
not here); a non-zero page-file field (bits 63:32 on Windows 10+) means paged out; an all-zero entry is
demand-zero or not mapped. Each refusal raises :class:`PageFault` with that reason.
"""

from __future__ import annotations

import struct
from typing import Callable, Dict, Iterator, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException

PRESENT, RW, USER, PS = 0x1, 0x2, 0x4, 0x80
PROTOTYPE, TRANSITION = 0x400, 0x800
NX = 1 << 63
ADDR = 0x000FFFFFFFFFF000
PAGE = 0x1000


class PageFault(InvalidAddressException):
    def __init__(self, va: int, reason: str, entry: Optional[int] = None):
        self.reason, self.entry = reason, entry
        super().__init__("virtual", va, "VA 0x%x: %s%s" % (va, reason, "" if entry is None else " (entry 0x%x)" % entry))


def canonical(va: int, levels: int = 4) -> int:
    bits = 57 if levels == 5 else 48
    va &= (1 << 64) - 1
    if va & (1 << (bits - 1)):
        return va | (((1 << 64) - 1) ^ ((1 << bits) - 1))
    return va & ((1 << bits) - 1)


class X64Paging:
    """Translation for one physical layer; page-table pages are cached (bounded)."""

    def __init__(self, phys_read: Callable[[int, int], bytes], levels: int = 4, cache_tables: int = 8192):
        if levels not in (4, 5):
            raise ValueError("levels must be 4 or 5")
        self._read, self.levels, self._cap = phys_read, levels, cache_tables
        self._tables: Dict[int, Tuple[int, ...]] = {}
        self.shifts = (48, 39, 30, 21, 12) if levels == 5 else (39, 30, 21, 12)

    def table(self, pa: int) -> Tuple[int, ...]:
        t = self._tables.get(pa)
        if t is None:
            t = struct.unpack("<512Q", self._read(pa, PAGE))
            if len(self._tables) >= self._cap:
                self._tables.clear()
            self._tables[pa] = t
        return t

    def translate(self, dtb: int, va: int) -> Tuple[int, int, int]:
        """``(physical address, page size, leaf entry)`` of ``va`` under ``dtb``."""
        table = dtb & ADDR
        for sh in self.shifts:
            try:
                e = self.table(table)[(va >> sh) & 0x1FF]
            except InvalidAddressException:
                raise PageFault(va, "page table at PA 0x%x not in the image" % table)
            last = sh == 12
            if not e & PRESENT:
                if e & PROTOTYPE:
                    raise PageFault(va, "prototype PTE (shared section, resolved through the VAD)", e)
                if e & TRANSITION and e & ADDR:
                    if last:
                        return (e & ADDR) | (va & 0xFFF), PAGE, e
                    table = e & ADDR  # page table itself on the standby/modified list
                    continue
                if e >> 32:
                    raise PageFault(va, "paged out (page file)", e)
                raise PageFault(va, "not mapped (demand zero or never touched)" if e == 0 else "not present", e)
            if sh in (30, 21) and e & PS:
                size = 1 << sh
                return (e & ADDR & ~(size - 1)) | (va & (size - 1)), size, e
            if last:
                return (e & ADDR) | (va & 0xFFF), PAGE, e
            table = e & ADDR
        raise PageFault(va, "walk failed")

    def mappings(self, dtb: int, start: int = 0, end: int = 1 << 64) -> Iterator[Tuple[int, int, int, int]]:
        """``(va, pa, size, entry)`` for every resident (present or transition) page in ``[start, end)``,
        in address order; unreadable page tables are skipped."""
        bits = 57 if self.levels == 5 else 48
        mask, half = (1 << bits) - 1, 1 << (bits - 1)
        upper = (1 << 64) - half  # first canonical address of the upper (kernel) half

        def walk(table_pa, level, base, rs, re_):
            sh = self.shifts[level]
            try:
                t = self.table(table_pa)
            except InvalidAddressException:
                return
            span = 1 << sh
            first = max(0, (rs - base) // span)
            last = min(511, (re_ - 1 - base) // span)
            for i in range(first, last + 1):
                e = t[i]
                if not (e & PRESENT or (e & TRANSITION and not e & PROTOTYPE and e & ADDR)):
                    continue
                raw = base + i * span
                if sh == 12 or (sh in (30, 21) and e & PS and e & PRESENT):
                    yield canonical(raw, self.levels), e & ADDR & ~(span - 1), span, e
                    continue
                for item in walk(e & ADDR, level + 1, raw, rs, re_):
                    yield item

        for lo, hi in ((start, min(end, half)), (max(start, upper), end)):
            if lo < hi:
                for item in walk(dtb & ADDR, 0, 0, lo & mask, ((hi - 1) & mask) + 1):
                    yield item
