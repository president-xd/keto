"""Volta+ runlists (NV_RAMRL_ENTRY_*): the scheduler's list of TSGs and channels.

Each entry is 16 bytes. A TSG (timeslice group) header is followed by
``TSG_LENGTH`` channel entries; each channel entry points at its USERD and its
instance block. Walking runlists is the GPU equivalent of walking
``ActiveProcessLinks``: it shows what the scheduler considers live, and
comparing it with signature-scanned instance blocks exposes channels that were
torn down or hidden from the scheduler.

    word0: TYPE 0 (0 chan, 1 TSG)
           chan: RUNQUEUE_SELECTOR 1, INST_TARGET 5:4, USERD_TARGET 7:6, USERD_PTR_LO 31:8
           TSG : TIMESLICE_SCALE 19:16, TIMESLICE_TIMEOUT 31:24
    word1: chan: USERD_PTR_HI          TSG: TSG_LENGTH 7:0
    word2: chan: CHID 11:0, INST_PTR_LO 31:12   TSG: TSGID 11:0
    word3: chan: INST_PTR_HI
"""

from __future__ import annotations

import re
import struct
from typing import Iterable, List, Optional, Set

from keto.framework.layers import DataLayer
from keto.framework.scanners import RegexScanner, scan
from keto.gpu.ramin import RAMIN_TARGETS, TARGET_CODES
from keto.gpu.gmmu import VID


class RunlistEntry:
    __slots__ = ("pa", "words", "type", "runq", "inst_aperture", "userd_aperture", "userd_addr", "chid",
                 "inst_addr", "timeslice_scale", "timeslice_timeout", "length", "tsgid")

    def __init__(self, pa, words):
        self.pa, self.words = pa, words
        w0, w1, w2, w3 = words
        self.type = "tsg" if w0 & 1 else "chan"
        self.runq = self.inst_aperture = self.userd_aperture = None
        self.userd_addr = self.chid = self.inst_addr = None
        self.timeslice_scale = self.timeslice_timeout = self.length = self.tsgid = None
        if self.type == "chan":
            self.runq = (w0 >> 1) & 1
            self.inst_aperture = RAMIN_TARGETS.get((w0 >> 4) & 3)
            self.userd_aperture = RAMIN_TARGETS.get((w0 >> 6) & 3)
            self.userd_addr = (w0 & 0xFFFFFF00) | (w1 << 32)
            self.chid = w2 & 0xFFF
            self.inst_addr = (w2 & 0xFFFFF000) | (w3 << 32)
        else:
            self.timeslice_scale = (w0 >> 16) & 0xF
            self.timeslice_timeout = (w0 >> 24) & 0xFF
            self.length = w1 & 0xFF
            self.tsgid = w2 & 0xFFF

    @property
    def timeslice_ticks(self) -> Optional[int]:
        if self.type != "tsg":
            return None
        return self.timeslice_timeout << self.timeslice_scale


class TsgGroup:
    def __init__(self, header: RunlistEntry, channels: List[RunlistEntry]):
        self.header, self.channels = header, channels


class Runlist:
    def __init__(self, pa: int, groups: List[TsgGroup]):
        self.pa, self.groups = pa, groups

    entry_size = 16

    @property
    def end(self) -> int:
        last = self.groups[-1]
        tail = last.channels[-1] if last.channels else last.header
        return tail.pa + self.entry_size

    def channels(self) -> Iterable[RunlistEntry]:
        for g in self.groups:
            yield from g.channels


def decode(data: bytes, pa: int, off: int = 0) -> RunlistEntry:
    return RunlistEntry(pa, struct.unpack_from("<IIII", data, off))


# TSG header: TYPE=1, scale<=15, timeout>0 / length 1..128 / tsgid<4096 / word3 = 0
_TSG_RE = re.compile(rb"\x01\x00[\x00-\x0f][\x01-\xff][\x01-\x80]\x00\x00\x00[\x00-\xff][\x00-\x0f]\x00\x00"
                     rb"\x00\x00\x00\x00", re.DOTALL)


def _plausible_channel(e: RunlistEntry, vram_size: Optional[int], known_inst: Set[int]) -> bool:
    if e.type != "chan" or not e.inst_addr or e.inst_aperture is None:
        return False
    if e.inst_addr in known_inst:
        return True
    if e.inst_aperture == VID and vram_size is not None and e.inst_addr >= vram_size:
        return False
    return e.userd_addr % 512 == 0


def parse_group(layer: DataLayer, pa: int, vram_size: Optional[int], known_inst: Set[int]) -> Optional[TsgGroup]:
    head = layer.read(pa, 16, pad=True)
    h = decode(head, pa)
    if h.type != "tsg" or not 1 <= (h.length or 0) <= 128:
        return None
    data = layer.read(pa + 16, 16 * h.length, pad=True)
    chans = []
    for i in range(h.length):
        e = decode(data, pa + 16 + 16 * i, 16 * i)
        if not _plausible_channel(e, vram_size, known_inst):
            return None
        chans.append(e)
    return TsgGroup(h, chans)


def scan_runlists(layer: DataLayer, vram_size: Optional[int] = None,
                  known_inst: Optional[Set[int]] = None) -> List[Runlist]:
    """Signature-scan for TSG headers, validate their channel entries, then chain
    contiguous groups into runlists."""
    known_inst = known_inst or set()
    groups = []
    for off, _ in scan(layer, RegexScanner(_TSG_RE, max_length=16, alignment=16)):
        g = parse_group(layer, off, vram_size, known_inst)
        if g:
            groups.append(g)
    groups.sort(key=lambda g: g.header.pa)
    runlists: List[Runlist] = []
    for g in groups:
        if runlists and runlists[-1].end == g.header.pa:
            runlists[-1].groups.append(g)
        else:
            runlists.append(Runlist(g.header.pa, [g]))
    return runlists


class RunlistEntry8(RunlistEntry):
    """Kepler..Pascal 8-byte runlist entry (nvgpu ram_rl_entry_*; word1 instance pointer per nouveau gm107+).

    word0: ID 11:0, TYPE 13 (1 = TSG), TSG: TIMESLICE_SCALE 17:14, TIMESLICE_TIMEOUT 25:18, TSG_LENGTH 31:26;
           channel (Pascal): RUNQUEUE 14
    word1: channel: instance block address >> 12 (Maxwell/Pascal); TSG: 0
    """

    def __init__(self, pa, w0, w1):  # noqa: super().__init__ not used: different word layout
        self.pa, self.words = pa, (w0, w1)
        self.type = "tsg" if w0 >> 13 & 1 else "chan"
        self.runq = self.inst_aperture = self.userd_aperture = None
        self.userd_addr = self.chid = self.inst_addr = None
        self.timeslice_scale = self.timeslice_timeout = self.length = self.tsgid = None
        if self.type == "tsg":
            self.tsgid, self.timeslice_scale = w0 & 0xFFF, (w0 >> 14) & 0xF
            self.timeslice_timeout, self.length = (w0 >> 18) & 0xFF, (w0 >> 26) & 0x3F
        else:
            self.chid, self.runq = w0 & 0xFFF, (w0 >> 14) & 1
            self.inst_addr, self.inst_aperture, self.userd_addr = w1 << 12, VID, 0


def scan_runlists_gm107(layer: DataLayer, known_inst: Set[int], vram_size: Optional[int] = None) -> List[Runlist]:
    """Maxwell/Pascal runlists: anchor on each known instance block's ``inst >> 12`` in word1, then grow the
    run of 8-byte entries backwards to its TSG header and forwards over the group's channels."""
    from keto.framework.scanners import BytesScanner
    found = {}
    for inst in sorted(known_inst):
        needle = struct.pack("<I", inst >> 12)
        for off, _ in scan(layer, BytesScanner(needle, alignment=4)):
            e_pa = off - 4
            if e_pa % 8:
                continue
            w0, w1 = struct.unpack("<II", layer.read(e_pa, 8, pad=True))
            e = RunlistEntry8(e_pa, w0, w1)
            if e.type == "chan" and e.inst_addr == inst:
                found[e_pa] = e
    groups = []
    for pa in sorted(found):
        head_pa = pa - 8
        while head_pa >= 0:
            w0, w1 = struct.unpack("<II", layer.read(head_pa, 8, pad=True))
            h = RunlistEntry8(head_pa, w0, w1)
            if h.type == "tsg":
                break
            head_pa -= 8
        else:
            continue
        if any(g.header.pa == head_pa for g in groups) or not 1 <= (h.length or 0) <= 32:
            continue
        data = layer.read(head_pa + 8, 8 * h.length, pad=True)
        chans = [RunlistEntry8(head_pa + 8 + 8 * i, *struct.unpack_from("<II", data, 8 * i)) for i in range(h.length)]
        if all(c.type == "chan" for c in chans):
            groups.append(TsgGroup(h, chans))
    groups.sort(key=lambda g: g.header.pa)
    runlists: List[Runlist] = []
    for g in groups:
        end = runlists[-1].groups[-1].channels[-1].pa + 8 if runlists else None
        if runlists and end == g.header.pa:
            runlists[-1].groups.append(g)
        else:
            runlists.append(Runlist(g.header.pa, [g]))
    for rl in runlists:  # Runlist.end assumes 16-byte entries
        rl.entry_size = 8
    return runlists


def scan_runlists_gk104(layer: DataLayer, chid_inst: dict, vram_size: Optional[int] = None) -> List[Runlist]:
    """Kepler runlists: 8-byte entries hold a channel id and no instance pointer. ``chid_inst`` maps each CHID
    read from an instance block's RAMFC to that block (``None`` when several blocks claim the CHID).

    A TSG group is accepted only if its header is well formed, every channel entry has word1 = 0 and every
    CHID is one some instance block claims; groups are found by anchoring on non-zero known CHIDs and are
    then extended over directly adjacent groups (which also picks up CHID 0)."""
    from keto.framework.scanners import BytesScanner

    def entry(pa):
        if pa < 0 or (vram_size and pa + 8 > vram_size):
            return None
        return RunlistEntry8(pa, *struct.unpack("<II", layer.read(pa, 8, pad=True)))

    def group_at(head_pa):
        h = entry(head_pa)
        if h is None or h.type != "tsg" or h.words[1] != 0 or not 1 <= h.length <= 32 or not h.timeslice_timeout:
            return None
        chans = [entry(head_pa + 8 * (i + 1)) for i in range(h.length)]
        if not all(c is not None and c.type == "chan" and c.words[1] == 0 and c.chid in chid_inst for c in chans):
            return None
        for c in chans:  # resolve the instance block through the CHID it holds in RAMFC
            c.inst_addr = chid_inst[c.chid]
            c.inst_aperture = VID if c.inst_addr is not None else None
            c.userd_addr = None
        return TsgGroup(h, chans)

    found = {}
    for chid in sorted(c for c in chid_inst if c):
        for off, _ in scan(layer, BytesScanner(struct.pack("<II", chid, 0), alignment=8)):
            for back in range(1, 33):  # the TSG header sits at most 32 entries before its channel
                g = group_at(off - 8 * back)
                if g and g.header.length >= back:
                    found[g.header.pa] = g
                    break
    changed = True
    while changed:  # grow over adjacent groups
        changed = False
        for pa, g in list(found.items()):
            nxt = pa + 8 * (g.header.length + 1)
            if nxt not in found and group_at(nxt):
                found[nxt], changed = group_at(nxt), True
            for back in range(2, 34):
                prev = pa - 8 * back
                if prev in found:
                    break
                pg = group_at(prev)
                if pg and pg.header.length + 1 == back:
                    found[prev], changed = pg, True
                    break
    runlists: List[Runlist] = []
    for pa in sorted(found):
        g = found[pa]
        if runlists and runlists[-1].groups[-1].channels[-1].pa + 8 == pa:
            runlists[-1].groups.append(g)
        else:
            runlists.append(Runlist(pa, [g]))
    for rl in runlists:
        rl.entry_size = 8
    return runlists


def encode_tsg8(tsgid: int, length: int, scale: int = 3, timeout: int = 128) -> bytes:
    return struct.pack("<II", (length << 26) | (timeout << 18) | (scale << 14) | 0x2000 | (tsgid & 0xFFF), 0)


def encode_channel8(chid: int, inst_addr: int, runq: int = 0) -> bytes:
    return struct.pack("<II", (chid & 0xFFF) | ((runq & 1) << 14), inst_addr >> 12)


def encode_tsg(tsgid: int, length: int, scale: int = 3, timeout: int = 128) -> bytes:
    return struct.pack("<IIII", (timeout << 24) | (scale << 16) | 1, length & 0xFF, tsgid & 0xFFF, 0)


def encode_channel(chid: int, inst_addr: int, userd_addr: int, runq: int = 0, inst_aperture: str = VID,
                   userd_aperture: str = VID) -> bytes:
    w0 = (userd_addr & 0xFFFFFF00) | (TARGET_CODES[userd_aperture] << 6) | (TARGET_CODES[inst_aperture] << 4) | \
        ((runq & 1) << 1)
    return struct.pack("<IIII", w0, userd_addr >> 32, (inst_addr & 0xFFFFF000) | (chid & 0xFFF), inst_addr >> 32)
