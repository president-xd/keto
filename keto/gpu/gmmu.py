"""NVIDIA GMMU page tables: decode, encode, walk, and expose as a layer.

Formats (bit fields copied from NVIDIA's published ``dev_mmu.h``):

VER2 (Pascal .. Ada), 49-bit VA, 5 levels::

    PD3 [48:47]  PD2 [46:38]  PD1 [37:29]  PD0 [28:21] (16-byte dual PDE)  PT [20:12] 4K / [20:16] 64K / [20:17] 128K

    PDE      APERTURE 2:1 (0 invalid, 1 vidmem, 2 sys-coherent, 3 sys-noncoherent), VOL 3,
             ADDRESS_SYS 53:8 / ADDRESS_VID 32:8, shift 12
    DUALPDE  APERTURE_BIG 2:1, VOL_BIG 3, ADDRESS_BIG_SYS 53:4 / _VID 32:4 (shift 8),
             APERTURE_SMALL 66:65, VOL_SMALL 67, ADDRESS_SMALL_SYS 117:72 / _VID 96:72 (shift 12)
    PTE      VALID 0, APERTURE 2:1 (0 vidmem, 1 peer, 2 sys-coh, 3 sys-noncoh), VOL 3, ENCRYPTED 4,
             PRIVILEGE 5, READ_ONLY 6, ATOMIC_DISABLE 7, ADDRESS_SYS 53:8 / ADDRESS_VID 32:8,
             PEER 35:33, COMPTAGLINE 53:36, KIND 63:56

VER3 (Hopper, Blackwell), 57-bit VA, 6 levels (PD4 [56:56] on top of the above)::

    PDE      IS_PTE 0, APERTURE 2:1, PCF 5:3, ADDRESS 51:12
    DUALPDE  APERTURE_BIG 2:1, PCF_BIG 5:3, ADDRESS_BIG 51:8 (shift 8),
             APERTURE_SMALL 66:65, PCF_SMALL 69:67, ADDRESS_SMALL 115:76
    PTE      VALID 0, APERTURE 2:1, PCF 7:3, KIND 11:8, ADDRESS 51:12, PEER_ID 63:61

Bit 0 of a directory entry marks a large page: a PD0 entry with bit 0 set is a
2 MiB PTE and a PD1 entry with bit 0 set is a 512 MiB PTE (same PTE format).
"""

from __future__ import annotations

import bisect
from typing import Dict, Iterator, List, Optional, Tuple

from keto.framework.layers import DataLayer

VID, PEER, SYS_COH, SYS_NCOH = "vidmem", "peer", "sysmem-coh", "sysmem-ncoh"
PDE_APERTURES = {0: None, 1: VID, 2: SYS_COH, 3: SYS_NCOH}
PTE_APERTURES = {0: VID, 1: PEER, 2: SYS_COH, 3: SYS_NCOH}
PDE_APERTURE_CODES = {VID: 1, SYS_COH: 2, SYS_NCOH: 3}
PTE_APERTURE_CODES = {VID: 0, PEER: 1, SYS_COH: 2, SYS_NCOH: 3}

PCF_INVALID_NAMES = {0: "INVALID", 1: "SPARSE", 2: "MAPPING_NOWHERE", 3: "NO_VALID_4KB_PAGE"}

M25 = (1 << 25) - 1
M29 = (1 << 29) - 1
M46 = (1 << 46) - 1
M50 = (1 << 50) - 1
ADDR52_4K = 0x000FFFFFFFFFF000
ADDR52_256 = 0x000FFFFFFFFFFF00


class Level:
    __slots__ = ("name", "hi", "lo", "entry_size")

    def __init__(self, name, hi, lo, entry_size):
        self.name, self.hi, self.lo, self.entry_size = name, hi, lo, entry_size

    @property
    def entries(self):
        return 1 << (self.hi - self.lo + 1)


class MmuFormat:
    def __init__(self, name: str, va_bits: int, levels: List[Level]):
        self.name, self.va_bits, self.levels = name, va_bits, levels


FORMATS = {
    # VER1 (Fermi/Kepler/Maxwell, Pascal in VER1 mode): 40-bit VA, one page directory of dual PDEs then a
    # big (64/128 KiB) or small (4 KiB) page table. The split depends on the big page size, so the walker
    # handles it specially (see GmmuWalker._walk_v1); this entry only carries the VA width.
    "v1": MmuFormat("v1", 40, []),
    "v2": MmuFormat("v2", 49, [Level("PD3", 48, 47, 8), Level("PD2", 46, 38, 8), Level("PD1", 37, 29, 8),
                               Level("PD0", 28, 21, 16)]),
    "v3": MmuFormat("v3", 57, [Level("PD4", 56, 56, 8), Level("PD3", 55, 47, 8), Level("PD2", 46, 38, 8),
                               Level("PD1", 37, 29, 8), Level("PD0", 28, 21, 16)]),
}


class Mapping:
    """One leaf translation (a page)."""

    __slots__ = ("va", "size", "pa", "aperture", "readonly", "privileged", "volatile", "encrypted",
                 "atomic_disable", "kind", "comptag", "peer_id", "pcf", "cached", "pte_pa", "raw", "level")

    def __init__(self, va, size, pa, aperture, raw, pte_pa, level, readonly=False, privileged=False,
                 volatile=False, encrypted=False, atomic_disable=False, kind=0, comptag=0, peer_id=0,
                 pcf=None, cached=True):
        self.va, self.size, self.pa, self.aperture = va, size, pa, aperture
        self.raw, self.pte_pa, self.level = raw, pte_pa, level
        self.readonly, self.privileged, self.volatile = readonly, privileged, volatile
        self.encrypted, self.atomic_disable, self.kind = encrypted, atomic_disable, kind
        self.comptag, self.peer_id, self.pcf, self.cached = comptag, peer_id, pcf, cached

    @property
    def end(self):
        return self.va + self.size

    def flags(self) -> str:
        f = ["RO" if self.readonly else "RW"]
        if self.privileged:
            f.append("PRIV")
        if self.volatile or not self.cached:
            f.append("UNCACHED" if self.pcf is not None else "VOL")
        if self.encrypted:
            f.append("ENC")
        if self.atomic_disable:
            f.append("NOATOMIC")
        return "|".join(f)

    def __repr__(self):
        return "<Mapping va=0x%x size=0x%x -> %s:0x%x %s kind=0x%x>" % (
            self.va, self.size, self.aperture, self.pa, self.flags(), self.kind)


# ----------------------------------------------------------------------------------------------
# entry decoders
# ----------------------------------------------------------------------------------------------
def decode_pde(fmt: str, raw: int) -> Optional[Tuple[str, int]]:
    ap = PDE_APERTURES[(raw >> 1) & 3]
    if ap is None:
        return None
    if fmt == "v3":
        return ap, raw & ADDR52_4K
    if ap == VID:
        return ap, ((raw >> 8) & M25) << 12
    return ap, ((raw >> 8) & M46) << 12


def decode_dual_pde(fmt: str, lo: int, hi: int):
    """Return ``(big, small)``; each is ``(aperture, table_pa)`` or None."""
    big = small = None
    ab = PDE_APERTURES[(lo >> 1) & 3]
    if ab is not None:
        if fmt == "v3":
            big = (ab, lo & ADDR52_256)
        else:
            big = (ab, (((lo >> 4) & (M29 if ab == VID else M50)) << 8))
    a_s = PDE_APERTURES[(hi >> 1) & 3]
    if a_s is not None:
        if fmt == "v3":
            small = (a_s, hi & ADDR52_4K)
        else:
            small = (a_s, (((hi >> 8) & (M25 if a_s == VID else M46)) << 12))
    return big, small


def decode_pte(fmt: str, raw: int, va: int, size: int, pte_pa: int, level: str) -> Optional[Mapping]:
    if not raw & 1:
        return None
    ap = PTE_APERTURES[(raw >> 1) & 3]
    if fmt == "v3":
        pcf = (raw >> 3) & 0x1F
        return Mapping(va, size, raw & ADDR52_4K, ap, raw, pte_pa, level,
                       readonly=bool(pcf & 4), privileged=bool(pcf & 2), cached=not (pcf & 1),
                       atomic_disable=bool(pcf & 8), kind=(raw >> 8) & 0xF,
                       peer_id=(raw >> 61) & 7 if ap == PEER else 0, pcf=pcf)
    if ap in (VID, PEER):
        pa = ((raw >> 8) & M25) << 12
        peer = (raw >> 33) & 7 if ap == PEER else 0
        comptag = (raw >> 36) & 0x3FFFF
    else:
        pa = ((raw >> 8) & M46) << 12
        peer, comptag = 0, 0
    return Mapping(va, size, pa, ap, raw, pte_pa, level,
                   volatile=bool(raw & 8), encrypted=bool(raw & 0x10), privileged=bool(raw & 0x20),
                   readonly=bool(raw & 0x40), atomic_disable=bool(raw & 0x80), kind=(raw >> 56) & 0xFF,
                   comptag=comptag, peer_id=peer)


# ----------------------------------------------------------------------------------------------
# VER1 (NVIDIA published maxwell/gm107 dev_mmu.h; docs/research/NVIDIA_HW_FACTS.md 1.2-1.4)
#   PDE: APERTURE_BIG 1:0, SIZE 3:2, ADDRESS_BIG 31:4 (VID 28:4), APERTURE_SMALL 33:32, VOL_SMALL 34,
#        VOL_BIG 35, ADDRESS_SMALL 63:36 (VID 60:36); addresses are PA >> 12
#   PTE: VALID 0, PRIVILEGE 1, READ_ONLY 2, ENCRYPTED 3, ADDRESS 31:4 (VID 28:4, PEER 31:29), VOL 32,
#        APERTURE 34:33, LOCK 35, KIND 43:36, COMPTAGLINE 60:44, READ_DISABLE 62, WRITE_DISABLE 63
# ----------------------------------------------------------------------------------------------
M28 = (1 << 28) - 1


def decode_pde_v1(raw: int):
    big = small = None
    ab = PDE_APERTURES[raw & 3]
    if ab is not None:
        big = (ab, ((raw >> 4) & (M25 if ab == VID else M28)) << 12)
    a_s = PDE_APERTURES[(raw >> 32) & 3]
    if a_s is not None:
        small = (a_s, ((raw >> 36) & (M25 if a_s == VID else M28)) << 12)
    return big, small


def decode_pte_v1(raw: int, va: int, size: int, pte_pa: int, level: str) -> Optional[Mapping]:
    if not raw & 1:
        return None
    ap = PTE_APERTURES[(raw >> 33) & 3]
    if ap in (VID, PEER):
        pa = ((raw >> 4) & M25) << 12
        peer = (raw >> 29) & 7 if ap == PEER else 0
    else:
        pa, peer = ((raw >> 4) & M28) << 12, 0
    return Mapping(va, size, pa, ap, raw, pte_pa, level, privileged=bool(raw & 2), readonly=bool(raw & 4),
                   encrypted=bool(raw & 8), volatile=bool(raw >> 32 & 1), kind=(raw >> 36) & 0xFF,
                   comptag=(raw >> 44) & 0x1FFFF, peer_id=peer)


def encode_pde_v1(big: Optional[Tuple[str, int]] = None, small: Optional[Tuple[str, int]] = None) -> int:
    raw = 0
    if big:
        raw |= PDE_APERTURE_CODES[big[0]] | ((big[1] >> 12) << 4)
    if small:
        raw |= (PDE_APERTURE_CODES[small[0]] << 32) | ((small[1] >> 12) << 36)
    return raw


def encode_pte_v1(aperture: str, addr: int, readonly=False, privileged=False, volatile=False, kind=0,
                  peer_id=0, encrypted=False, **_ignored) -> int:
    raw = 1 | (int(privileged) << 1) | (int(readonly) << 2) | (int(encrypted) << 3) | ((addr >> 12) << 4) | \
        (int(volatile) << 32) | (PTE_APERTURE_CODES[aperture] << 33) | ((kind & 0xFF) << 36)
    if aperture == PEER:
        raw |= (peer_id & 7) << 29
    return raw


def v1_split(big_page_size: int):
    """``(pd_shift, big_shift)``: PD index is VA 39:pd_shift; big PT index pd_shift-1:big_shift."""
    big_shift = big_page_size.bit_length() - 1
    return big_shift + 10, big_shift


# ----------------------------------------------------------------------------------------------
# entry encoders (used by the synthetic image builder and by tests)
# ----------------------------------------------------------------------------------------------
def encode_pde(fmt: str, aperture: str, addr: int, vol: bool = False) -> int:
    code = PDE_APERTURE_CODES[aperture]
    if fmt == "v3":
        return (addr & ADDR52_4K) | (code << 1)
    return ((addr >> 12) << 8) | (code << 1) | (int(vol) << 3)


def encode_dual_pde(fmt: str, big: Optional[Tuple[str, int]] = None,
                    small: Optional[Tuple[str, int]] = None) -> Tuple[int, int]:
    lo = hi = 0
    if big:
        ap, addr = big
        lo = (addr & ADDR52_256) | (PDE_APERTURE_CODES[ap] << 1) if fmt == "v3" else \
            ((addr >> 8) << 4) | (PDE_APERTURE_CODES[ap] << 1)
    if small:
        ap, addr = small
        hi = (addr & ADDR52_4K) | (PDE_APERTURE_CODES[ap] << 1) if fmt == "v3" else \
            ((addr >> 12) << 8) | (PDE_APERTURE_CODES[ap] << 1)
    return lo, hi


def encode_pte(fmt: str, aperture: str, addr: int, readonly=False, privileged=False, volatile=False,
               kind=0, peer_id=0, encrypted=False, atomic_disable=False, uncached=False) -> int:
    code = PTE_APERTURE_CODES[aperture]
    if fmt == "v3":
        pcf = int(uncached) | (int(privileged) << 1) | (int(readonly) << 2) | (int(atomic_disable) << 3)
        return 1 | (code << 1) | (pcf << 3) | ((kind & 0xF) << 8) | (addr & ADDR52_4K) | ((peer_id & 7) << 61)
    raw = 1 | (code << 1) | (int(volatile) << 3) | (int(encrypted) << 4) | (int(privileged) << 5) | \
        (int(readonly) << 6) | (int(atomic_disable) << 7) | ((addr >> 12) << 8) | ((kind & 0xFF) << 56)
    if aperture == PEER:
        raw |= (peer_id & 7) << 33
    return raw


# ----------------------------------------------------------------------------------------------
# walker
# ----------------------------------------------------------------------------------------------
class WalkEvent:
    """A node of the page-table tree (for ``nvidia.ptwalk``)."""

    __slots__ = ("depth", "level", "index", "entry_pa", "raw", "va", "kind", "target", "note")

    def __init__(self, depth, level, index, entry_pa, raw, va, kind, target=None, note=""):
        self.depth, self.level, self.index, self.entry_pa = depth, level, index, entry_pa
        self.raw, self.va, self.kind, self.target, self.note = raw, va, kind, target, note


class GmmuWalker:
    """Walk one GPU address space rooted at a page directory base (PDB)."""

    def __init__(self, aperture_layers: Dict[str, Optional[DataLayer]], pdb: int, fmt: str = "v2",
                 pdb_aperture: str = VID, big_page_size: int = 65536, vram_size: Optional[int] = None):
        if fmt not in FORMATS:
            raise ValueError("unknown MMU format %r" % fmt)
        self.layers = aperture_layers
        self.pdb, self.fmt, self.pdb_aperture = pdb, fmt, pdb_aperture
        self.big_page_size = big_page_size
        self.big_shift = big_page_size.bit_length() - 1
        self.vram_size = vram_size
        self.stats = {"tables": 0, "unreadable_tables": 0, "out_of_range": 0, "bad_large_pde": 0,
                      "sparse_ptes": 0}
        self._mappings: Optional[List[Mapping]] = None

    # -- low level -----------------------------------------------------------
    def _layer_for(self, aperture: str) -> Optional[DataLayer]:
        if aperture in (SYS_COH, SYS_NCOH):
            return self.layers.get(aperture) or self.layers.get("sysmem")
        return self.layers.get(aperture)

    def _read_table(self, aperture: str, pa: int, size: int) -> Optional[bytes]:
        layer = self._layer_for(aperture)
        if aperture == VID and self.vram_size is not None and pa + size > self.vram_size:
            self.stats["out_of_range"] += 1
            return None
        if layer is None or not layer.is_valid(pa, size):
            self.stats["unreadable_tables"] += 1
            return None
        self.stats["tables"] += 1
        return layer.read(pa, size)

    # -- traversal ------------------------------------------------------------
    def events(self) -> Iterator[WalkEvent]:
        """Depth-first walk yielding every non-empty entry (directories and leaves)."""
        if self.fmt == "v1":
            yield from self._walk_v1()
            return
        yield from self._walk_level(0, self.pdb_aperture, self.pdb, 0)

    def _walk_v1(self) -> Iterator[WalkEvent]:
        pd_shift, big_shift = v1_split(self.big_page_size)
        n = 1 << (40 - pd_shift)
        data = self._read_table(self.pdb_aperture, self.pdb, n * 8)
        if data is None:
            yield WalkEvent(0, "PD", -1, self.pdb, 0, 0, "unreadable", note="page directory not readable")
            return
        words = memoryview(data).cast("Q")
        for i in range(n):
            raw = words[i]
            if not raw:
                continue
            va = i << pd_shift
            entry_pa = self.pdb + i * 8
            big, small = decode_pde_v1(raw)
            if big is None and small is None:
                yield WalkEvent(0, "PD", i, entry_pa, raw, va, "invalid", note="invalid apertures")
                continue
            yield WalkEvent(0, "PD", i, entry_pa, raw, va, "dual", (big, small))
            for which, ptr, shift in (("big", big, big_shift), ("small", small, 12)):
                if ptr is None:
                    continue
                cnt = 1 << (pd_shift - shift)
                name = "PT-%s" % ("4K" if shift == 12 else "%dK" % ((1 << shift) >> 10))
                tbl = self._read_table(ptr[0], ptr[1], cnt * 8)
                if tbl is None:
                    yield WalkEvent(1, name, -1, ptr[1], 0, va, "unreadable", note="table not readable")
                    continue
                if tbl.count(0) == len(tbl):
                    continue
                tw = memoryview(tbl).cast("Q")
                for j in range(cnt):
                    pte = tw[j]
                    if not pte:
                        continue
                    pva = va | (j << shift)
                    m = decode_pte_v1(pte, pva, 1 << shift, ptr[1] + j * 8, which)
                    yield WalkEvent(1, name, j, ptr[1] + j * 8, pte, pva, "pte" if m else "invalid", m,
                                    "" if m else "invalid PTE")

    def _walk_level(self, idx, aperture, table_pa, va_base) -> Iterator[WalkEvent]:
        levels = FORMATS[self.fmt].levels
        level = levels[idx]
        data = self._read_table(aperture, table_pa, level.entries * level.entry_size)
        if data is None:
            yield WalkEvent(idx, level.name, -1, table_pa, 0, va_base, "unreadable", note="table not readable")
            return
        if data.count(0) == len(data):
            return
        words = memoryview(data).cast("Q")
        dual = level.entry_size == 16
        for i in range(level.entries):
            va = va_base | (i << level.lo)
            entry_pa = table_pa + i * level.entry_size
            if dual:
                lo, hi = words[2 * i], words[2 * i + 1]
                if not lo and not hi:
                    continue
                if lo & 1:
                    m = decode_pte(self.fmt, lo, va, 1 << level.lo, entry_pa, "2M")
                    yield WalkEvent(idx, level.name, i, entry_pa, lo, va, "pte", m)
                    continue
                big, small = decode_dual_pde(self.fmt, lo, hi)
                yield WalkEvent(idx, level.name, i, entry_pa, lo | (hi << 64), va, "dual", (big, small))
                if big:
                    yield from self._walk_pt(idx + 1, big[0], big[1], va, self.big_shift, "big")
                if small:
                    yield from self._walk_pt(idx + 1, small[0], small[1], va, 12, "small")
            else:
                raw = words[i]
                if not raw:
                    continue
                if raw & 1:
                    if level.name == "PD1":
                        m = decode_pte(self.fmt, raw, va, 1 << level.lo, entry_pa, "512M")
                        yield WalkEvent(idx, level.name, i, entry_pa, raw, va, "pte", m)
                    else:
                        self.stats["bad_large_pde"] += 1
                        yield WalkEvent(idx, level.name, i, entry_pa, raw, va, "anomaly",
                                        note="bit0 set on %s (no large pages at this level)" % level.name)
                    continue
                pde = decode_pde(self.fmt, raw)
                if pde is None:
                    yield WalkEvent(idx, level.name, i, entry_pa, raw, va, "invalid", note="invalid aperture")
                    continue
                yield WalkEvent(idx, level.name, i, entry_pa, raw, va, "pde", pde)
                yield from self._walk_level(idx + 1, pde[0], pde[1], va)

    def _walk_pt(self, depth, aperture, table_pa, va_base, page_shift, which) -> Iterator[WalkEvent]:
        n = 1 << (21 - page_shift)
        name = "PT-%s" % ("4K" if page_shift == 12 else "%dK" % ((1 << page_shift) >> 10))
        data = self._read_table(aperture, table_pa, n * 8)
        if data is None:
            yield WalkEvent(depth, name, -1, table_pa, 0, va_base, "unreadable", note="table not readable")
            return
        words = memoryview(data).cast("Q")
        for i in range(n):
            raw = words[i]
            if not raw:
                continue
            va = va_base | (i << page_shift)
            entry_pa = table_pa + i * 8
            m = decode_pte(self.fmt, raw, va, 1 << page_shift, entry_pa, which)
            if m is None:
                if self.fmt == "v3":
                    self.stats["sparse_ptes"] += 1
                    note = PCF_INVALID_NAMES.get((raw >> 3) & 0x1F, "invalid")
                else:
                    note = "invalid PTE"
                yield WalkEvent(depth, name, i, entry_pa, raw, va, "invalid", note=note)
                continue
            yield WalkEvent(depth, name, i, entry_pa, raw, va, "pte", m)

    def mappings(self) -> List[Mapping]:
        if self._mappings is None:
            self._mappings = sorted((e.target for e in self.events() if e.kind == "pte" and e.target is not None),
                                    key=lambda m: (m.va, m.size))
        return self._mappings


class GmmuLayer(DataLayer):
    """A GPU virtual address space as a readable layer.

    Translation prefers the smallest page that covers an address (a valid 4K PTE
    overrides a big page in the same 2 MiB region, as the hardware does when a
    dual PDE has both tables).
    """

    KIND = "gpu-va"

    def __init__(self, name: str, walker: GmmuWalker):
        super().__init__(name)
        self.walker = walker
        self._index: Optional[Dict[int, Dict[int, Mapping]]] = None
        self._ranges: Optional[List[Tuple[int, int]]] = None

    def _build(self):
        idx: Dict[int, Dict[int, Mapping]] = {}
        for m in self.walker.mappings():
            shift = m.size.bit_length() - 1
            idx.setdefault(shift, {})[m.va >> shift] = m
        self._index = idx
        self._shifts = sorted(idx)
        readable = []
        for m in self.walker.mappings():
            layer = self.walker._layer_for(m.aperture)
            if layer is not None and layer.is_valid(m.pa, m.size):
                readable.append((m.va, m.size))
        readable.sort()
        merged: List[Tuple[int, int]] = []
        for s, l in readable:
            if merged and s <= merged[-1][0] + merged[-1][1]:
                ps, pl = merged[-1]
                merged[-1] = (ps, max(pl, s + l - ps))
            else:
                merged.append((s, l))
        self._ranges = merged

    def ranges(self):
        if self._ranges is None:
            self._build()
        return self._ranges

    def translate(self, va: int) -> Optional[Tuple[Mapping, int]]:
        """Return ``(mapping, physical_address)`` or None."""
        if self._index is None:
            self._build()
        for shift in self._shifts:
            m = self._index[shift].get(va >> shift)
            if m is not None:
                return m, m.pa + (va - m.va)
        return None

    def _read_run(self, offset, length):
        out = bytearray()
        pos, end = offset, offset + length
        while pos < end:
            t = self.translate(pos)
            if t is None:  # can only happen if ranges() and translate disagree
                out += b"\x00" * (end - pos)
                break
            m, pa = t
            take = min(end, m.va + m.size) - pos
            # a smaller page may start inside this one: stop at the next 4K boundary when not 4K itself
            if m.size > 4096:
                nxt = (pos // 4096 + 1) * 4096
                for shift in self._shifts:
                    if (1 << shift) < m.size:
                        take = min(take, nxt - pos)
                        break
            layer = self.walker._layer_for(m.aperture)
            out += layer.read(pa, take, pad=True)
            pos += take
        return bytes(out)

    def mappings(self) -> List[Mapping]:
        return self.walker.mappings()

    def reverse(self, pa: int, aperture: str = VID) -> List[Tuple[int, Mapping]]:
        """All VAs mapping physical address ``pa`` (slow path, linear)."""
        out = []
        for m in self.walker.mappings():
            if m.aperture == aperture and m.pa <= pa < m.pa + m.size:
                out.append((m.va + (pa - m.pa), m))
        return out


def coalesce(mappings: List[Mapping]) -> List[dict]:
    """Merge VA-contiguous mappings that are also PA-contiguous with identical attributes."""
    regions: List[dict] = []
    for m in mappings:
        key = (m.aperture, m.readonly, m.privileged, m.kind, m.size, m.volatile, m.encrypted, m.cached, m.peer_id)
        if regions:
            r = regions[-1]
            if r["key"] == key and r["va"] + r["size"] == m.va and r["pa"] + r["size"] == m.pa:
                r["size"] += m.size
                r["pages"] += 1
                continue
        regions.append({"key": key, "va": m.va, "pa": m.pa, "size": m.size, "pages": 1, "first": m})
    return regions


def build_reverse_index(mappings: List[Mapping]) -> Tuple[List[int], List[Mapping]]:
    """Sorted-by-PA index for fast physical->virtual lookups."""
    vid = sorted((m for m in mappings if m.aperture == VID), key=lambda m: m.pa)
    return [m.pa for m in vid], vid


def reverse_lookup(index: Tuple[List[int], List[Mapping]], pa: int) -> List[Mapping]:
    starts, maps = index
    out = []
    i = bisect.bisect_right(starts, pa) - 1
    # pages can be up to 512 MiB; walk back while candidates could still cover pa
    while i >= 0:
        m = maps[i]
        if m.pa <= pa < m.pa + m.size:
            out.append(m)
        if pa - m.pa > (1 << 29):
            break
        i -= 1
    return out
