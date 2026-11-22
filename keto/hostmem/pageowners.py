"""Who owns a host physical page: reverse map from page frame to the processes (and virtual addresses) that map
it, built by walking every task's user page tables in kernel memory (RAM image or /proc/kcore).

x86-64 user half: PML4 entries 0..255 (4-level) or PML5 entries 0..255 (5-level). Present bit 0, writable bit 1,
user bit 2, PS bit 7 (1 GiB / 2 MiB pages), NX bit 63. Pages no task maps are classified as kernel image (between
``_text`` and ``_end``) or other kernel memory (slab, page cache, page tables, free).
"""

from __future__ import annotations

import bisect
import struct
from typing import Dict, Iterable, List, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException
from keto.hostmem.btf import BtfError
from keto.hostmem.dxg import walk_tasks
from keto.hostmem.linux import START_KERNEL_MAP, KernelMemory, PTE_ADDR

PAGE = 0x1000


class Owner:
    __slots__ = ("pid", "comm", "va", "writable", "executable")

    def __init__(self, pid, comm, va, writable, executable):
        self.pid, self.comm, self.va, self.writable, self.executable = pid, comm, va, writable, executable

    def __repr__(self):
        return "%s(%d)@0x%x%s" % (self.comm, self.pid, self.va, " rw" if self.writable else "")


def user_pages(km: KernelMemory, pgd_pa: int, targets: Optional[List[int]] = None
               ) -> Iterable[Tuple[int, int, int, bool, bool]]:
    """Yield ``(va, pa, size, writable, executable)`` for every present user mapping under ``pgd_pa``. With
    ``targets`` (sorted page-aligned physical addresses), leaf tables whose range cannot contain a target are still
    walked but only matching pages are yielded (huge pages are tested by range)."""
    shifts = (48, 39, 30, 21, 12) if km.l5 else (39, 30, 21, 12)

    def rd(pa):
        return km.read_phys(pa, PAGE)

    def walk(table_pa, level, va_base):
        sh = shifts[level]
        try:
            raw = rd(table_pa)
        except InvalidAddressException:
            return
        limit = 256 if level == 0 else 512  # level 0: user half only
        for i in range(limit):
            e = struct.unpack_from("<Q", raw, i * 8)[0]
            if not e & 1:
                continue
            va = va_base | (i << sh)
            base = e & PTE_ADDR
            rw, nx = bool(e & 2), bool(e >> 63)
            if sh == 12 or (sh in (30, 21) and e & 0x80):
                size = 1 << sh
                base &= ~(size - 1)
                if targets is not None:
                    j = bisect.bisect_left(targets, base)
                    if j == len(targets) or targets[j] >= base + size:
                        continue
                yield va, base, size, rw, not nx
            else:
                yield from walk(base, level + 1, va)

    yield from walk(pgd_pa, 0, 0)


def _pgd_pa(km: KernelMemory, mm_va: int) -> Optional[int]:
    try:
        pgd_va = km.obj("mm_struct", mm_va)["pgd"]
    except (InvalidAddressException, BtfError):
        return None
    if not pgd_va:
        return None
    if km.kcore is not None:
        return pgd_va - km.page_offset_base  # page tables live in the direct map
    try:
        return km.v2p(pgd_va)
    except InvalidAddressException:
        return None


def owners(km: KernelMemory, pages: Iterable[int], errors: Optional[List[str]] = None) -> Dict[int, List[Owner]]:
    """``page physical address -> [Owner]`` for every task mapping one of ``pages`` (4 KiB aligned). With
    ``errors``, a broken task list gives the owners found among the tasks reached and records the error there
    (owners of later tasks are missing) instead of raising."""
    targets = sorted({p & ~(PAGE - 1) for p in pages})
    out: Dict[int, List[Owner]] = {p: [] for p in targets}
    if not targets:
        return out
    seen_mm = set()
    for t in walk_tasks(km, errors=errors):
        mm = t.get("mm")
        if not mm or mm in seen_mm:
            continue
        seen_mm.add(mm)
        pgd = _pgd_pa(km, mm)
        if pgd is None:
            continue
        for va, pa, size, rw, x in user_pages(km, pgd, targets):
            j = bisect.bisect_left(targets, pa)
            while j < len(targets) and targets[j] < pa + size:
                out[targets[j]].append(Owner(t["pid"], t["comm"], va + (targets[j] - pa), rw, x))
                j += 1
    return out


def kernel_image_range(km: KernelMemory) -> Optional[Tuple[int, int]]:
    """Physical range of the kernel image (``_text`` .. ``_end``), when the symbols and phys_base are known."""
    s, e = km.symbols.get("_text"), km.symbols.get("_end")
    if s is None or e is None or km.phys_base is None:
        return None
    return s - START_KERNEL_MAP + km.phys_base, e - START_KERNEL_MAP + km.phys_base


def classify(km: KernelMemory, pa: int, page_owners: List[Owner]) -> str:
    if page_owners:
        return "user: " + ", ".join("%s(%d)" % (o.comm, o.pid) for o in page_owners[:6]) + \
            (" +%d" % (len(page_owners) - 6) if len(page_owners) > 6 else "")
    rng = kernel_image_range(km)
    if rng and rng[0] <= pa < rng[1]:
        return "KERNEL IMAGE (text/data)"
    return "kernel memory (not mapped by any process: slab, page cache, page tables or free)"
