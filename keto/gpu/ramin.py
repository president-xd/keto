"""Channel instance blocks (RAMIN), the embedded FIFO context (RAMFC) and USERD.

An instance block is a 4 KiB, 4 KiB-aligned structure the GPU keeps for every
channel. Its first 512 bytes are the RAMFC (the PBDMA's saved state: GPFIFO
base and size, GET/PUT pointers, USERD address, semaphore state); at 0x200 it
holds the channel's page directory base; Volta+ adds a table of per-subcontext
page directory bases at 0x2A0. RAMFC word 4 carries the hardware signature
``0xFACE`` (``NV_PPBDMA_SIGNATURE_HW_VALID``) which makes instance blocks
scannable exactly like Windows ``_EPROCESS`` pool tags.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from keto.framework.layers import DataLayer
from keto.gpu.gmmu import SYS_COH, SYS_NCOH, VID

#: NV_RAMIN_PAGE_DIR_BASE_TARGET / USERD / runlist INST targets
RAMIN_TARGETS = {0: VID, 1: None, 2: SYS_COH, 3: SYS_NCOH}
TARGET_CODES = {VID: 0, SYS_COH: 2, SYS_NCOH: 3}


class SubcontextPdb:
    __slots__ = ("veid", "aperture", "pdb", "ver2", "big_page_size", "ats", "pasid", "raw")

    def __init__(self, veid, aperture, pdb, ver2, big_page_size, ats, pasid, raw):
        self.veid, self.aperture, self.pdb, self.ver2 = veid, aperture, pdb, ver2
        self.big_page_size, self.ats, self.pasid, self.raw = big_page_size, ats, pasid, raw


class InstanceBlock:
    """Decoded instance block. Attributes are None when the profile has no such field."""

    def __init__(self, pa: int):
        self.pa = pa
        self.score = 0
        self.reasons: List[str] = []
        self.fields: Dict[str, int] = {}
        self.signature = 0
        self.signature_ok = False
        self.userd_aperture: Optional[str] = None
        self.userd_addr = 0
        self.gp_base_va = 0
        self.gp_limit2 = 0
        self.pdb_aperture: Optional[str] = None
        self.pdb = 0
        self.pdb_vol = False
        self.pdb_ver2 = False
        self.big_page_size = 65536
        self.fault_replay = (False, False)
        self.privileged = False
        self.chid_hint: Optional[int] = None
        self.veid: Optional[int] = None
        self.pasid: Optional[int] = None
        self.ats = False
        self.engine_wfi_ptr = 0
        self.engine_wfi: Dict[str, object] = {}
        self.method_buffer = 0
        self.subcontexts: List[SubcontextPdb] = []
        # USERD-derived state, filled by ``read_userd``
        self.userd: Dict[str, int] = {}

    @property
    def gp_entries(self) -> int:
        return 1 << self.gp_limit2 if self.gp_limit2 else 0

    @property
    def valid(self) -> bool:
        return self.signature_ok and self.pdb_aperture is not None and self.score >= 5

    def gp_get(self) -> Optional[int]:
        return self.userd.get("gp_get", self.fields.get("gp_get"))

    def gp_put(self) -> Optional[int]:
        return self.userd.get("gp_put", self.fields.get("gp_put"))

    def address_spaces(self):
        """``[(label, aperture, pdb, ver2, big_page_size)]`` for main + subcontexts."""
        out = [("main", self.pdb_aperture, self.pdb, self.pdb_ver2, self.big_page_size)]
        for sc in self.subcontexts:
            out.append(("veid%d" % sc.veid, sc.aperture, sc.pdb, sc.ver2, sc.big_page_size))
        return out

    def __repr__(self):
        return "<InstanceBlock pa=0x%x pdb=%s:0x%x gpfifo=0x%x x%d score=%d>" % (
            self.pa, self.pdb_aperture, self.pdb, self.gp_base_va, self.gp_entries, self.score)


def _w(data: bytes, off: Optional[int]) -> int:
    if off is None or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def _field(data: bytes, spec) -> int:
    """Read bit field ``[byte_offset, hi, lo]`` (layout spec) from a structure image."""
    if not spec or spec[0] is None:
        return 0
    off, hi, lo = spec
    return (_w(data, off) >> lo) & ((1 << (hi - lo + 1)) - 1)


def _decode_pdb_word(lo: int, hi: int):
    target = RAMIN_TARGETS[lo & 3]
    vol = bool(lo & 4)
    replay_tex, replay_gcc = bool(lo & 0x10), bool(lo & 0x20)
    ver2 = bool(lo & (1 << 10))
    big = 65536 if lo & (1 << 11) else 131072
    addr = (lo & 0xFFFFF000) | (hi << 32)
    return target, addr, vol, ver2, big, (replay_tex, replay_gcc)


def parse_instance_block(layer: DataLayer, pa: int, profile, vram_size: Optional[int] = None,
                         data: Optional[bytes] = None) -> InstanceBlock:
    """Decode the instance block at ``pa`` and score how plausible it is."""
    ramin, fc = profile.ramin, profile.ramfc
    size = ramin.get("size", 0x1000)
    if data is None:
        data = layer.read(pa, size, pad=True)
    ib = InstanceBlock(pa)
    for name, off in fc.items():
        if isinstance(off, int) and name not in ("size", "signature_mask", "signature_value", "hce_priv_bit"):
            ib.fields[name] = _w(data, off)

    ib.signature = ib.fields.get("signature", 0)
    ib.signature_ok = (ib.signature & fc.get("signature_mask", 0xFFFF)) == fc.get("signature_value", 0xFACE)
    if ib.signature_ok:
        ib.score += 3
        ib.reasons.append("RAMFC signature 0x%04x" % (ib.signature & 0xFFFF))
    magic = ramin.get("magic")
    if magic and _w(data, magic[0]) == magic[1]:
        ib.score += 1
        ib.reasons.append("RAMIN marker 0x%08x" % magic[1])

    # page directory base (NV_RAMIN_PAGE_DIR_BASE_*)
    lo, hi = _w(data, ramin.get("page_dir_base_lo")), _w(data, ramin.get("page_dir_base_hi"))
    target, addr, vol, ver2, big, replay = _decode_pdb_word(lo, hi)
    ib.pdb_aperture, ib.pdb, ib.pdb_vol, ib.pdb_ver2, ib.big_page_size, ib.fault_replay =         target, addr, vol, ver2, big, replay
    if target is not None and addr and addr % 4096 == 0 and (target != VID or vram_size is None or addr < vram_size):
        ib.score += 2
        ib.reasons.append("page directory %s:0x%x" % (target, addr))
    else:
        ib.pdb_aperture = None

    # GPFIFO ring: GP_BASE (offset 31:3) + GP_BASE_HI (offset hi bits) and LIMIT2 (log2 entries), whose
    # location and width differ per generation (layout specs gp_base_hi_bits / gp_limit2)
    gpl, gph = ib.fields.get("gp_base_lo", 0), ib.fields.get("gp_base_hi", 0)
    hi_bits = fc.get("gp_base_hi_bits", 8)
    ib.gp_base_va = (gpl & 0xFFFFFFF8) | ((gph & ((1 << hi_bits) - 1)) << 32)
    ib.gp_limit2 = _field(data, fc.get("gp_limit2") or [fc.get("gp_base_hi"), 20, 16])
    if ib.gp_base_va and 1 <= ib.gp_limit2 <= 24:
        ib.score += 2
        ib.reasons.append("GPFIFO 0x%x x%d" % (ib.gp_base_va, ib.gp_entries))

    # USERD (NV_PPBDMA_USERD: target 1:0, addr 31:9; hi 7:0) - only in RAMFC up to Turing; from Ampere on
    # it is known only from the runlist entry (filled in by discovery)
    if "userd_lo" in fc:
        ul, uh = ib.fields.get("userd_lo", 0), ib.fields.get("userd_hi", 0)
        ib.userd_aperture = RAMIN_TARGETS.get(ul & 3)
        ib.userd_addr = (ul & 0xFFFFFE00) | ((uh & 0xFF) << 32)
        if ib.userd_addr and ib.userd_aperture:
            ib.score += 1

    bit = fc.get("hce_priv_bit")
    if bit is not None and "hce_ctrl" in ib.fields:
        ib.privileged = bool(ib.fields["hce_ctrl"] & (1 << bit))
    ib.chid_hint = _field(data, fc["chid"]) if fc.get("chid") else None

    if "engine_wfi_veid" in ramin:
        ib.veid = _w(data, ramin["engine_wfi_veid"]) & 0x3F
    if "engine_wfi_lo" in ramin:
        wl, wh = _w(data, ramin["engine_wfi_lo"]), _w(data, ramin.get("engine_wfi_hi"))
        ib.engine_wfi_ptr = (wl & 0xFFFFF000) | ((wh & 0xFF) << 32)
        # NV_RAMIN_ENGINE_WFI_TARGET 1:0 (0 local, 2 sys-coh, 3 sys-noncoh), _MODE 2 (0 physical, 1 virtual),
        # NV_RAMIN_ENGINE_CS 3 (0 WFI, 1 FG)
        ib.engine_wfi = {"target": {0: VID, 2: SYS_COH, 3: SYS_NCOH}.get(wl & 3, "invalid"),
                         "mode": "virtual" if wl & 4 else "physical", "cs": "FG" if wl & 8 else "WFI",
                         "ptr": ib.engine_wfi_ptr}
    if "eng_method_buffer_lo" in ramin:
        ib.method_buffer = _w(data, ramin["eng_method_buffer_lo"]) | \
            ((_w(data, ramin.get("eng_method_buffer_hi")) & 0x1FFFF) << 32)
    if "pasid" in ramin:
        pw = _w(data, ramin["pasid"])
        ib.pasid, ib.ats = pw & 0xFFFFF, bool(pw >> 31)

    # Volta+ subcontext page directories (NV_RAMIN_SC_*)
    count = ramin.get("sc_count", 0)
    if count and "sc_pdb_valid" in ramin:
        mask = _w(data, ramin["sc_pdb_valid"]) | (_w(data, ramin["sc_pdb_valid"] + 4) << 32)
        base, stride = ramin["sc_page_dir_base"], ramin.get("sc_stride", 16)
        for veid in range(count):
            if not mask >> veid & 1:
                continue
            o = base + veid * stride
            slo, shi, sw2 = _w(data, o), _w(data, o + 4), _w(data, o + 8)
            st, saddr, _, sver2, sbig, _ = _decode_pdb_word(slo, shi)
            if st is None or not saddr:
                continue
            ib.subcontexts.append(SubcontextPdb(veid, st, saddr, sver2, sbig, bool(sw2 >> 31), sw2 & 0xFFFFF,
                                                (slo, shi, sw2)))
    return ib


def read_userd(ib: InstanceBlock, layers: Dict[str, DataLayer], profile) -> None:
    """Fill ``ib.userd`` from the USERD page (GP_GET/GP_PUT/PUT/GET...)."""
    layer = layers.get(ib.userd_aperture) if ib.userd_aperture else None
    if layer is None and ib.userd_aperture in (SYS_COH, SYS_NCOH):
        layer = layers.get("sysmem")
    ud = profile.userd
    size = ud.get("size", 0x200)
    if layer is None or not ib.userd_addr or not layer.is_valid(ib.userd_addr, size):
        return
    data = layer.read(ib.userd_addr, size)
    for name, off in ud.items():
        if name != "size":
            ib.userd[name] = _w(data, off)


def encode_instance_block(profile, *, pdb: int, pdb_aperture: str = VID, ver2: bool = True,
                          big_page_size: int = 65536, gp_base_va: int, gp_limit2: int,
                          userd_addr: int, userd_aperture: str = VID, gp_get: int = 0, gp_put: int = 0,
                          privileged: bool = False, chid: int = 0, veid: int = 0,
                          subcontexts: Optional[List[tuple]] = None, engine_ctx_va: int = 0) -> bytes:
    """Build an instance block image (synthetic test data). ``subcontexts`` is a list of
    ``(veid, aperture, pdb)``."""
    ramin, fc = profile.ramin, profile.ramfc
    buf = bytearray(ramin.get("size", 0x1000))

    def put(off, val):
        if off is not None:
            struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)

    def put_field(spec, val):
        off, hi, lo = spec
        mask = ((1 << (hi - lo + 1)) - 1) << lo
        cur = struct.unpack_from("<I", buf, off)[0]
        struct.pack_into("<I", buf, off, (cur & ~mask) | ((val << lo) & mask))

    put(fc["signature"], fc.get("signature_value", 0xFACE))
    if "userd_lo" in fc:
        put(fc["userd_lo"], (userd_addr & 0xFFFFFE00) | TARGET_CODES[userd_aperture])
        put(fc.get("userd_hi"), userd_addr >> 32)
    hi_bits = fc.get("gp_base_hi_bits", 8)
    put(fc.get("gp_base_lo"), gp_base_va & 0xFFFFFFF8)
    put(fc.get("gp_base_hi"), (gp_base_va >> 32) & ((1 << hi_bits) - 1))
    put_field(fc.get("gp_limit2") or [fc.get("gp_base_hi"), 20, 16], gp_limit2)
    put(fc.get("gp_get"), gp_get)
    put(fc.get("gp_put"), gp_put)
    if fc.get("hce_ctrl") is not None:
        put(fc["hce_ctrl"], (1 << fc.get("hce_priv_bit", 5)) if privileged else 0)
    if fc.get("chid"):
        put_field(fc["chid"], chid)
    if ramin.get("magic"):
        put(ramin["magic"][0], ramin["magic"][1])

    def pdb_word(target, addr, v2, big):
        return (addr & 0xFFFFF000) | TARGET_CODES[target] | (int(v2) << 10) | ((1 if big == 65536 else 0) << 11)

    put(ramin["page_dir_base_lo"], pdb_word(pdb_aperture, pdb, ver2, big_page_size))
    put(ramin["page_dir_base_hi"], pdb >> 32)
    if "engine_wfi_veid" in ramin:
        put(ramin["engine_wfi_veid"], veid)
    if engine_ctx_va and "engine_wfi_lo" in ramin:
        put(ramin["engine_wfi_lo"], (engine_ctx_va & 0xFFFFF000) | 4)  # target local, mode virtual, WFI
        put(ramin["engine_wfi_hi"], (engine_ctx_va >> 32) & 0xFF)
    if subcontexts and ramin.get("sc_count"):
        mask = 0
        for sveid, sap, spdb in subcontexts:
            mask |= 1 << sveid
            o = ramin["sc_page_dir_base"] + sveid * ramin.get("sc_stride", 16)
            put(o, pdb_word(sap, spdb, ver2, big_page_size))
            put(o + 4, spdb >> 32)
        put(ramin["sc_pdb_valid"], mask & 0xFFFFFFFF)
        put(ramin["sc_pdb_valid"] + 4, mask >> 32)
    return bytes(buf)


def encode_userd(profile, gp_get: int, gp_put: int, put: int = 0, get: int = 0) -> bytes:
    ud = profile.userd
    buf = bytearray(ud.get("size", 0x200))
    for name, val in (("gp_get", gp_get), ("gp_put", gp_put), ("put", put), ("get", get)):
        if name in ud:
            struct.pack_into("<I", buf, ud[name], val)
    return bytes(buf)
