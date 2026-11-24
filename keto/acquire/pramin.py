"""``keto acquire --method pramin``: physical VRAM through the BAR0 PRAMIN window (Linux, root).

The GPU decodes a 1 MiB aperture at BAR0 + 0x700000 (``NV_PRAMIN``) onto VRAM starting at the 64 KiB-aligned
address held in a window register: ``NV_PBUS_BAR0_WINDOW`` (0x1700, BASE 23:0, TARGET 25:24) up to Ada, and
``NV_XAL_EP_BAR0_WINDOW`` (0x10fd40, BASE only) on Hopper, Blackwell and Rubin. Every register address, field and
error value used here is cited in docs/research/NVIDIA_HW_FACTS.md, Topic 7. A chip with no cited window register
is refused; a chip with no cited VRAM-size register needs NVML or ``--vram-size``.

Moving the window changes state a bound driver depends on: nouveau and NVIDIA's RM cache the window position and
do not re-read it, so a driver access while Keto holds the window reaches the wrong VRAM (docs/ACQUISITION.md SOP).
The method therefore refuses a bound GPU driver unless ``--allow-bound-driver`` is given, and:

* saves the window register before the first write and restores it on every exit path (normal end, exceptions,
  SIGINT/SIGTERM/SIGHUP: the handlers only set a flag that the read loop checks between aperture reads, so no
  signal can interrupt the restore). When another agent moved the window meanwhile, the value it wrote last is
  restored, because that is what the driver's cached position says the register holds;
* reads back and verifies every window write;
* re-reads the window register after every aperture read; a block read while someone else had moved the window
  is discarded and read again (bounded retries), and every such event is recorded;
* reads MMIO with aligned 32-bit loads (``--bulk-mmio`` switches to memcpy);
* stores every page, zero pages included: the VRAM layer reads only what a container holds, so omitted pages
  would not read back as zeros. Pages made only of PRI error words are stored as read and listed in
  ``pramin.error_ranges``.

Structure: ``Host`` (where preconditions look: sysfs root, platform, euid, BAR0 opener, NVML; tests substitute a
fake sysfs tree and ``keto.testing.fakebar0``), ``Bar0Mmio`` (the real accessor), ``identify`` (BOOT_0/BOOT_42 ->
chip), ``PraminReader`` (window discipline) and ``acquire_pramin``.
"""

from __future__ import annotations

import array
import ctypes
import errno
import hashlib
import mmap
import os
import platform
import re
import signal
import struct
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from keto.formats.container import ContainerWriter
from keto.framework.exceptions import KetoError, RequirementError

PAGE = 0x1000
APERTURE = 0x700000            # NV_PRAMIN 0x007FFFFF:0x00700000                       (HW facts 7.1)
APERTURE_SIZE = 0x100000
WINDOW_SHIFT = 16              # *_BAR0_WINDOW_BASE_SHIFT                              (7.2, 7.3)
WINDOW_ALIGN = 1 << WINDOW_SHIFT
BLOCK = 0x10000                # bytes read between two checks of the window register
BOOT_0, BOOT_42 = 0x000000, 0x000A00   # NV_PMC_BOOT_0, NV_PMC_BOOT_42                  (5.1)
ALL_ONES = 0xFFFFFFFF          # what a read returns when the GPU no longer responds (RM GPU_REG_VALUE_INVALID)
SEC_FAULT = 0xBADF0200         # NV_XAL_EP_ZB_SCPM_PRI_DUMMY_DATA_PATTERN_INIT (RM: SEC_FAULT if BOOT_0 reads it)
RETRIES = 4                    # extra attempts when the window was moved by someone else
NVIDIA = 0x10DE                # PCI_VENDOR_ID_NVIDIA
DISPLAY_CLASSES = {0x0300: "VGA", 0x0302: "3D"}  # PCI_CLASS_DISPLAY_VGA / _3D
PCI_COMMAND, PCI_COMMAND_MEMORY = 0x04, 0x2
MAX_EVENTS = 256               # window events kept in the metadata (all are counted)

#: Bits 31:8 of a 32-bit read that report a PRI error instead of data (HW facts 7.6): NV_PPRIV_SYS_PRI_ERROR_CODE
#: values (NVIDIA), the GF119 MMIO error families observed by envytools, and the Hopper+ SCPM dummy pattern.
PRI_ERROR_CODES = frozenset((
    0xBAD00F, 0xBAD001, 0xBAD0B0,                                            # HOST_FECS_ERR/PRI_TIMEOUT/FB_ACK
    0xBADF10, 0xBADF11, 0xBADF12, 0xBADF13, 0xBADF14, 0xBADF15, 0xBADF16, 0xBADF17,   # FECS_PRI_*
    0xBADF20, 0xBADF30, 0xBADF40, 0xBADF50,                                  # ORPHAN, DEAD_RING, TRAP, CLIENT
    0xBAD0AC, 0xBAD0DA, 0xBAD0FB,                                            # envytools: VM fault, disabled, mem
    0xBADF02,                                                                # SCPM dummy data (SEC_FAULT)
))
_TOP_BA = b"\xba" * (PAGE // 4)  # every word's top byte is 0xBA: cheap pre-filter before the exact test
_ONES = b"\xff" * PAGE
_WORD = array.array("I").itemsize == 4 and "I" or "L"


class PraminError(KetoError):
    """The window could not be programmed, verified or kept, or the GPU stopped responding."""


class AcquisitionInterrupted(KeyboardInterrupt):
    """SIGINT/SIGTERM/SIGHUP arrived during the acquisition (raised from the read loop, never from a handler)."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum
        try:
            self.name = signal.Signals(signum).name
        except ValueError:
            self.name = "signal %d" % signum

    def __str__(self):
        return "interrupted by %s" % self.name


def is_pri_error(word: int) -> bool:
    return (word >> 8) in PRI_ERROR_CODES


def _valid_reg(v: int) -> bool:
    return v != ALL_ONES and (v & 0xFFF00000) != 0xBAD00000  # RM: 0xbad in the top 3 nibbles is a possible error


# -- architecture -------------------------------------------------------------------------------------------------

class WindowRegister:
    """How one architecture positions the PRAMIN window (HW facts 7.2, 7.3)."""

    def __init__(self, name: str, offset: int, base_hi: int, target: bool, source: str):
        self.name, self.offset, self.has_target, self.source = name, offset, target, source
        self.base_bits = "%d:0" % base_hi
        self.base_mask = (1 << (base_hi + 1)) - 1
        self.mask = self.base_mask | (0x3 << 24 if target else 0)

    @property
    def max_vram(self) -> int:
        """First VRAM address the BASE field cannot reach."""
        return (self.base_mask + 1) << WINDOW_SHIFT

    def value(self, current: int, vram_base: int) -> int:
        """Register value that puts the window at ``vram_base`` (TARGET = VID_MEM where the field exists). Bits
        outside BASE/TARGET keep their current value (a read-modify-write, as RM's field writes do)."""
        if vram_base % WINDOW_ALIGN or vram_base < 0 or vram_base >= self.max_vram:
            raise ValueError("window base 0x%x is not 64 KiB aligned or exceeds %s BASE %s"
                             % (vram_base, self.name, self.base_bits))
        return (current & ~self.mask & 0xFFFFFFFF) | (vram_base >> WINDOW_SHIFT)

    def describe(self, value: int) -> str:
        base = (value & self.base_mask) << WINDOW_SHIFT
        if self.has_target:
            target = ("VID_MEM", "reserved", "SYS_MEM_COHERENT", "SYS_MEM_NONCOHERENT")[(value >> 24) & 3]
            return "0x%08x (TARGET %s, base 0x%x)" % (value, target, base)
        return "0x%08x (base 0x%x)" % (value, base)

    def as_dict(self) -> dict:
        d = {"name": self.name, "offset": "0x%x" % self.offset, "base_bits": self.base_bits,
             "base_shift": WINDOW_SHIFT, "source": self.source}
        if self.has_target:
            d["target_bits"] = "25:24"
        return d


WIN_PBUS = WindowRegister("NV_PBUS_BAR0_WINDOW", 0x1700, 23, True,
                          "gm107 dev_bus.h; RM kbusSetBAR0WindowVidOffset_GM107 (TU10x..AD10x); nova-core TU102 "
                          "MM HAL (Turing/Ampere/Ada); nouveau nv50_instmem (Kepler..Ada); envytools PBUS.PMEM")
WIN_GH100 = WindowRegister("NV_XAL_EP_BAR0_WINDOW", 0x10FD40, 21, False,
                           "gh100 dev_nv_xal_ep_zb.h (0xd40, BASE 21:0) + hwproject.h NV_XAL_BASE_ADDRESS 0x10f000; "
                           "nova-core gh100 NV_XAL_EP_BAR0_WINDOW @ 0x0010fd40")
WIN_GB100 = WindowRegister("NV_XAL_EP_BAR0_WINDOW", 0x10FD40, 22, False,
                           "gb100 dev_nv_xal_ep_zb.h (0xd40, BASE 22:0); RM kbusWriteBAR0WindowBase_GB100 "
                           "(GB100..GB207); nova-core gb100 NV_XAL_EP_BAR0_WINDOW @ 0x0010fd40")
WIN_GR100 = WindowRegister("NV_XAL_EP_BAR0_WINDOW", 0x10FD40, 30, False,
                           "gr100 dev_nv_xal_ep_zb.h (0xD40, BASE 47-17:0); RM kbusWriteBAR0WindowBase_GR100 with "
                           "the XAL aperture of kbusConstructXalApertures_GH100 (address derived, 0x10f000 + 0xd40)")

#: chipset (BOOT_42 architecture << 4 | implementation) -> (chip, generation = Keto profile name)   (HW facts 5.4)
CHIPS: Dict[int, Tuple[str, str]] = {}
for _gen, _ids in (
        ("kepler", ((0x0E4, "GK104"), (0x0E6, "GK106"), (0x0E7, "GK107"), (0x0F0, "GK110"), (0x0F1, "GK110B"),
                    (0x106, "GK208B"), (0x108, "GK208"))),
        ("maxwell", ((0x117, "GM107"), (0x118, "GM108"), (0x120, "GM200"), (0x124, "GM204"), (0x126, "GM206"))),
        ("pascal", ((0x130, "GP100"), (0x132, "GP102"), (0x134, "GP104"), (0x136, "GP106"), (0x137, "GP107"),
                    (0x138, "GP108"))),
        ("volta", ((0x140, "GV100"),)),
        ("turing", ((0x162, "TU102"), (0x164, "TU104"), (0x166, "TU106"), (0x167, "TU117"), (0x168, "TU116"))),
        ("ampere", ((0x170, "GA100"), (0x172, "GA102"), (0x173, "GA103"), (0x174, "GA104"), (0x176, "GA106"),
                    (0x177, "GA107"))),
        ("hopper", ((0x180, "GH100"),)),
        ("ada", ((0x192, "AD102"), (0x193, "AD103"), (0x194, "AD104"), (0x196, "AD106"), (0x197, "AD107"))),
        ("blackwell", ((0x1A0, "GB100"), (0x1A2, "GB102"), (0x1A3, "GB110"), (0x1A4, "GB112"), (0x1B2, "GB202"),
                       (0x1B3, "GB203"), (0x1B5, "GB205"), (0x1B6, "GB206"), (0x1B7, "GB207"))),
        ("rubin", ((0x1C0, "GR100"), (0x1C2, "GR102")))):
    for _cs, _name in _ids:
        CHIPS[_cs] = (_name, _gen)
#: integrated (Tegra-class) GPUs: no dedicated VRAM behind a PCI BAR0 window; GB10B-class XAL apertures differ
INTEGRATED = {0x0EA: "GK20A", 0x12B: "GM20B", 0x12E: "GM20B_B", 0x13B: "GP10B", 0x14B: "GV10B", 0x15B: "GV11B",
              0x17B: "GA10B", 0x1AB: "GB10B", 0x1AC: "GB10C", 0x1BB: "GB20B", 0x1BC: "GB20C"}
WINDOW_BY_GEN = {"kepler": WIN_PBUS, "maxwell": WIN_PBUS, "pascal": WIN_PBUS, "volta": WIN_PBUS,
                 "turing": WIN_PBUS, "ampere": WIN_PBUS, "ada": WIN_PBUS, "hopper": WIN_GH100,
                 "blackwell": WIN_GB100, "rubin": WIN_GR100}

#: VRAM-size registers (HW facts 7.5): which chips RM's kmemsysReadUsableFbSize HAL reads them on
LOCAL_MEMORY_RANGE = 0x100CE0   # NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE (gp102 dev_fb.h): SCALE 3:0, MAG 9:4, ECC 30
USABLE_FB_SIZE_IN_MB = 0x1183A4  # NV_USABLE_FB_SIZE_IN_MB = NV_PGC6_AON_SECURE_SCRATCH_GROUP_42 (ga102)
SIZE_REGISTER = {cs: LOCAL_MEMORY_RANGE for cs in (0x162, 0x164, 0x166, 0x167, 0x168, 0x170)}
SIZE_REGISTER.update({cs: USABLE_FB_SIZE_IN_MB for cs in (0x172, 0x173, 0x174, 0x176, 0x177, 0x192, 0x193, 0x194,
                                                          0x196, 0x197, 0x180, 0x1A0, 0x1A2, 0x1A3, 0x1A4, 0x1B2,
                                                          0x1B3, 0x1B5, 0x1B6, 0x1B7, 0x1C0, 0x1C2)})


class Chip:
    def __init__(self, chipset: int, name: str, generation: str, boot0: int, boot42: Optional[int], notes: List[str]):
        self.chipset, self.name, self.generation = chipset, name, generation
        self.boot0, self.boot42, self.notes = boot0, boot42, notes
        self.window = WINDOW_BY_GEN[generation]
        self.size_register = SIZE_REGISTER.get(chipset)


def identify(mmio) -> Chip:
    """Decode NV_PMC_BOOT_0 (and NV_PMC_BOOT_42 on Pascal and later; nova-core identifies Turing+ by BOOT_42 only)
    into a chip from the cited table, or refuse."""
    boot0 = mmio.read32(BOOT_0)
    if boot0 == ALL_ONES:
        raise RequirementError("NV_PMC_BOOT_0 reads 0xffffffff: the GPU does not respond (powered down, memory "
                               "decoding off, or fallen off the bus); nothing was written")
    if boot0 == SEC_FAULT:
        raise RequirementError("NV_PMC_BOOT_0 reads the SCPM dummy pattern 0xbadf0200: the GPU is in SEC_FAULT "
                               "(every PRI read returns that pattern); VRAM cannot be read through PRAMIN")
    if not _valid_reg(boot0):
        raise RequirementError("NV_PMC_BOOT_0 reads 0x%08x, a PRI error value: the GPU is not answering register "
                               "reads; nothing was written" % boot0)
    arch0, arch1 = (boot0 >> 24) & 0x1F, (boot0 >> 8) & 1
    if arch1 == 0 and arch0 < 0x0C:
        raise RequirementError("NV_PMC_BOOT_0 0x%08x: a chip older than Fermi (architecture 0x%x); not supported"
                               % (boot0, arch0))
    chipset = (boot0 >> 20) & 0x1FF
    notes: List[str] = []
    boot42 = None
    if arch1 or arch0 >= 0x13:  # Pascal and later carry NV_PMC_BOOT_42
        boot42 = mmio.read32(BOOT_42)
        if _valid_reg(boot42) and boot42:
            cs42 = (((boot42 >> 24) & 0x3F) << 4) | ((boot42 >> 20) & 0xF)
            if cs42 != chipset:
                notes.append("BOOT_0 chip id 0x%03x differs from BOOT_42 0x%03x; BOOT_42 used" % (chipset, cs42))
            chipset = cs42
        elif arch1 or arch0 >= 0x16:
            raise RequirementError("NV_PMC_BOOT_42 reads 0x%08x on a Turing-or-later GPU (BOOT_0 0x%08x): the chip "
                                   "cannot be identified" % (boot42, boot0))
    if chipset in INTEGRATED:
        raise RequirementError("chipset 0x%03x (%s) is an integrated GPU: it has no dedicated VRAM behind a BAR0 "
                               "PRAMIN window (and GB10B-class XAL apertures differ); not supported"
                               % (chipset, INTEGRATED[chipset]))
    if 0x0C0 <= chipset < 0x0E0:
        raise RequirementError("chipset 0x%03x is a Fermi GPU, outside Keto's architecture profiles (Kepler..Rubin): "
                               "not supported" % chipset)
    if chipset not in CHIPS:
        raise RequirementError("chipset 0x%03x (BOOT_0 0x%08x%s) is not in the chip list of "
                               "docs/research/NVIDIA_HW_FACTS.md (5.4, 7.4): no cited PRAMIN window register for it; "
                               "refusing to guess one"
                               % (chipset, boot0, ", BOOT_42 0x%08x" % boot42 if boot42 is not None else ""))
    name, gen = CHIPS[chipset]
    return Chip(chipset, name, gen, boot0, boot42, notes)


def size_from_register(mmio, chip: Chip) -> Tuple[Optional[int], str]:
    """VRAM size from the chip's cited register: ``(bytes or None, description)``."""
    reg = chip.size_register
    if reg is None:
        return None, "no cited VRAM-size register for %s (%s)" % (chip.name, chip.generation)
    v = mmio.read32(reg)
    if reg == LOCAL_MEMORY_RANGE:
        what = "NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE (0x%x) = 0x%08x" % (reg, v)
        if not _valid_reg(v):
            return None, what + ": not a valid value"
        scale, mag, ecc = v & 0xF, (v >> 4) & 0x3F, (v >> 30) & 1
        size = mag << (scale + 20)
        if ecc:
            size = size // 16 * 15
        what += ": LOWER_MAG %d << (LOWER_SCALE %d + 20)%s" % (mag, scale, ", ECC on: x15/16" if ecc else "")
    else:
        what = "NV_USABLE_FB_SIZE_IN_MB (0x%x) = 0x%08x" % (reg, v)
        if not _valid_reg(v):
            return None, what + ": not a valid value"
        size = v << 20
        what += " MiB"
    if size <= 0:
        return None, what + ": zero"
    return size, what


# -- MMIO -----------------------------------------------------------------------------------------------------------

class Bar0Mmio:
    """BAR0 through a shared mapping of sysfs ``resource0`` (any file works, which is how it is tested). Aligned
    32-bit loads and stores go through ctypes ``c_uint32`` objects at the mapped address; ``read_words`` reads a
    range as a ctypes ``c_uint32`` array, element by element (one 4-byte load each, in C), and ``read_bulk`` is a
    plain memcpy (the CPU may use wider loads: only with ``--bulk-mmio``)."""

    def __init__(self, fd: int, size: int):
        self.size = size
        self._fd = fd
        self._mm = mmap.mmap(fd, size, access=mmap.ACCESS_WRITE)
        self._buf = (ctypes.c_char * size).from_buffer(self._mm)
        self._base = ctypes.addressof(self._buf)

    @classmethod
    def open(cls, path: str, size: Optional[int] = None) -> "Bar0Mmio":
        fd = os.open(path, os.O_RDWR | getattr(os, "O_BINARY", 0))
        try:
            return cls(fd, size if size is not None else os.fstat(fd).st_size)
        except BaseException:
            os.close(fd)
            raise

    def _check(self, offset: int, length: int):
        if self._mm is None:
            raise ValueError("BAR0 mapping is closed")
        if offset % 4 or length % 4 or length <= 0 or offset < 0 or offset + length > self.size:
            raise ValueError("MMIO access 0x%x+0x%x is unaligned or outside BAR0 (0x%x bytes)"
                             % (offset, length, self.size))

    def read32(self, offset: int) -> int:
        self._check(offset, 4)
        return ctypes.c_uint32.from_address(self._base + offset).value

    def write32(self, offset: int, value: int) -> None:
        self._check(offset, 4)
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("0x%x does not fit a 32-bit register" % value)
        ctypes.c_uint32.from_address(self._base + offset).value = value

    def read_words(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        words = (ctypes.c_uint32 * (length // 4)).from_address(self._base + offset)
        out = array.array(_WORD, words[:])
        if sys.byteorder != "little":
            out.byteswap()
        return out.tobytes()

    def read_bulk(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        return ctypes.string_at(self._base + offset, length)

    def close(self):
        if self._mm is not None:
            del self._buf
            self._mm.close()
            self._mm = None
            os.close(self._fd)


# -- window discipline ------------------------------------------------------------------------------------------------

class PraminReader:
    """Reads VRAM through the PRAMIN aperture. ``read(base, addr, n)`` returns ``n`` bytes at VRAM ``addr`` with the
    window at ``base`` (``addr - base + n`` within the 1 MiB aperture); ``restore()`` puts the window back."""

    def __init__(self, mmio, window: WindowRegister, bulk: bool = False, retries: int = RETRIES,
                 boot0: Optional[int] = None):
        self.mmio, self.window, self.retries, self.boot0 = mmio, window, retries, boot0
        self._load = mmio.read_bulk if bulk else mmio.read_words
        self.original = mmio.read32(window.offset)  # saved before anything is written
        self.foreign = self.original   # last value seen that this reader did not write: what to restore
        self.last_written: Optional[int] = None
        self.current: Optional[int] = None          # window base known to be programmed
        self.dirty = False
        self.writes = 0
        self.events: List[dict] = []
        self.moved = 0                 # aperture reads discarded because the window had moved
        self.moved_between = 0         # moves found when re-programming (no data affected)
        self.readback_failures = 0
        self.restored_to: Optional[int] = None
        self.after: Optional[int] = None
        self.restore_verified: Optional[bool] = None

    def _same(self, a: int, b: Optional[int]) -> bool:
        return b is not None and (a & self.window.mask) == (b & self.window.mask)

    def _event(self, kind: str, **kw):
        if len(self.events) < MAX_EVENTS:
            kw = {k: ("0x%x" % v if isinstance(v, int) and k != "attempt" else v) for k, v in kw.items()}
            self.events.append(dict(kind=kind, **kw))

    def check_alive(self, addr: int):
        """RM's test after an all-ones read: if NV_PMC_BOOT_0 no longer reads its value, the GPU is gone."""
        b0 = self.mmio.read32(BOOT_0)
        if self.boot0 is not None and b0 != self.boot0:
            raise PraminError("NV_PMC_BOOT_0 now reads 0x%08x (was 0x%08x) after an all-ones read at VRAM 0x%x: the "
                              "GPU stopped responding or was reset; acquisition stopped" % (b0, self.boot0, addr))

    def _program(self, base: int):
        for attempt in range(self.retries + 1):
            cur = self.mmio.read32(self.window.offset)
            if cur == ALL_ONES:
                self.check_alive(base)
            if self.last_written is not None and not self._same(cur, self.last_written) \
                    and not self._same(cur, self.foreign):
                self.foreign = cur
                self.moved_between += 1
                self._event("moved-between-reads", observed=cur, expected=self.last_written, attempt=attempt)
            want = self.window.value(cur, base)
            self.dirty = True  # set before the write: a restore after any write attempt is always safe
            self.mmio.write32(self.window.offset, want)
            self.writes += 1
            back = self.mmio.read32(self.window.offset)
            if self._same(back, want):
                self.last_written, self.current = back, base
                return
            self.readback_failures += 1
            self.current = None
            self._event("readback-mismatch", wrote=want, read=back, vram=base, attempt=attempt)
            if not self._same(back, cur):
                self.foreign = back  # someone else wrote it in between
        raise PraminError("%s did not keep 0x%08x (window base 0x%x): read back 0x%08x after %d attempt(s). The "
                          "register is locked or another agent keeps writing it; acquisition stopped"
                          % (self.window.name, want, base, back, self.retries + 1))

    def read(self, base: int, addr: int, n: int) -> bytes:
        off = addr - base
        if base % WINDOW_ALIGN or off < 0 or off + n > APERTURE_SIZE or n % 4 or off % 4:
            raise ValueError("aperture read VRAM 0x%x+0x%x with window 0x%x is outside the 1 MiB aperture"
                             % (addr, n, base))
        for attempt in range(self.retries + 1):
            if self.current != base:
                self._program(base)
            data = self._load(APERTURE + off, n)
            after = self.mmio.read32(self.window.offset)
            if self._same(after, self.last_written):
                return data
            if after == ALL_ONES:
                self.check_alive(addr)
            self.moved += 1
            self.current = None
            if not self._same(after, self.foreign):
                self.foreign = after
            self._event("moved-during-read", vram=addr, length=n, expected=self.last_written, observed=after,
                        attempt=attempt)
        raise PraminError("the PRAMIN window was moved by another agent (a bound driver) during %d consecutive "
                          "reads at VRAM 0x%x; acquisition stopped (bounded retries)" % (self.retries + 1, addr))

    def restore(self) -> bool:
        """Write back the value the register should hold for everyone else and verify it."""
        if not self.dirty:
            self.after = self.mmio.read32(self.window.offset)
            self.restore_verified = True
            return True
        target = self.foreign
        self.restored_to = target
        for _ in range(self.retries + 1):
            self.mmio.write32(self.window.offset, target)
            self.writes += 1
            back = self.mmio.read32(self.window.offset)
            if self._same(back, target):
                self.after = back
                self.restore_verified = True
                self.dirty = False
                return True
            self.after = back
        self.restore_verified = False
        return False

    def metadata(self) -> dict:
        w = self.window
        return {"window_before": "0x%08x" % self.original, "window_before_decoded": w.describe(self.original),
                "window_restored_to": None if self.restored_to is None else "0x%08x" % self.restored_to,
                "window_restored_reason": (None if self.restored_to is None else
                                           "original value" if self.restored_to == self.original else
                                           "last value written by another agent during the acquisition (the "
                                           "driver's cached window position)"),
                "window_after": None if self.after is None else "0x%08x" % self.after,
                "window_restore_verified": self.restore_verified, "window_writes": self.writes,
                "window_moved_during_read": self.moved, "window_moved_between_reads": self.moved_between,
                "window_readback_failures": self.readback_failures, "window_events": self.events,
                "window_events_total": self.moved + self.moved_between + self.readback_failures}


class _SignalGuard:
    """While VRAM is read, SIGINT/SIGTERM/SIGHUP only record that they arrived; the read loop calls ``check()``
    between aperture reads and raises there, so the window restore in the ``finally`` block is never cut short.
    SIGKILL cannot be caught: it leaves the window wherever it was."""

    NAMES = ("SIGINT", "SIGTERM", "SIGHUP")

    def __init__(self, err):
        self.err = err
        self.pending: Optional[int] = None
        self.saved: Dict[int, object] = {}

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            raise RequirementError("the pramin method must run in the main thread: signal handlers that protect "
                                   "the window restore can only be installed there")
        for name in self.NAMES:
            sig = getattr(signal, name, None)
            if sig is not None:
                self.saved[sig] = signal.signal(sig, self._handle)
        return self

    def _handle(self, signum, _frame):
        if self.pending is None:
            self.pending = signum
            self.err.write("\nsignal %d received: stopping after the current aperture read; the PRAMIN window will "
                           "be restored\n" % signum)

    def check(self):
        if self.pending is not None:
            raise AcquisitionInterrupted(self.pending)

    def __exit__(self, *exc):
        for sig, handler in self.saved.items():
            signal.signal(sig, handler)
        return False


# -- host / preconditions ----------------------------------------------------------------------------------------------

class Host:
    """Everything the method inspects on the acquiring machine. Tests pass a temporary ``sysfs_root`` holding a fake
    sysfs tree, a platform name and euid, and an ``open_bar0`` that returns an emulated BAR0."""

    def __init__(self, sysfs_root: str = "/sys", system: Optional[str] = None, euid: Optional[int] = None,
                 open_bar0: Optional[Callable] = None, nvml: Optional[Callable] = None, err=None):
        self.sysfs_root = sysfs_root
        self.system = system if system is not None else platform.system()
        self._euid = euid
        self.open_bar0 = open_bar0 or Bar0Mmio.open
        self._nvml = nvml
        self.err = err if err is not None else sys.stderr

    def euid(self) -> Optional[int]:
        if self._euid is not None:
            return self._euid
        return os.geteuid() if hasattr(os, "geteuid") else None

    def path(self, *parts) -> str:
        return os.path.join(self.sysfs_root, *parts)

    def nvml(self) -> Optional[dict]:
        if self._nvml is not None:
            return self._nvml()
        try:
            from keto.live.source import SystemSource
            return SystemSource().nvml()
        except Exception:  # NVML is only a VRAM-size fallback
            return None


def default_host() -> Host:
    return Host()


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="ascii", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def _int(text: Optional[str]) -> Optional[int]:
    try:
        return int(text, 0) if text else None
    except ValueError:
        return None


def _uevent(devdir: str) -> Dict[str, str]:
    out = {}
    for line in (_read_text(os.path.join(devdir, "uevent")) or "").splitlines():
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


BDF_RE = re.compile(r"^(?:([0-9a-f]{4,8}):)?([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])$")


def normalize_bdf(text: str) -> str:
    m = BDF_RE.match(text.strip().lower())
    if not m:
        raise RequirementError("--pci %r: expected a PCI address such as 0000:01:00.0 or 01:00.0" % text)
    return "%04x:%s:%s.%s" % (int(m.group(1) or "0", 16), m.group(2), m.group(3), m.group(4))


class PciDevice:
    def __init__(self, devdir: str):
        self.dir = devdir
        ue = _uevent(devdir)
        slot = ue.get("PCI_SLOT_NAME") or os.path.basename(devdir)  # the kernel's own name for the slot
        try:
            self.bdf = normalize_bdf(slot)
        except RequirementError:
            self.bdf = slot
        self.vendor = _int(_read_text(os.path.join(devdir, "vendor")))
        self.device = _int(_read_text(os.path.join(devdir, "device")))
        self.cls = _int(_read_text(os.path.join(devdir, "class")))
        self.subsystem = (_int(_read_text(os.path.join(devdir, "subsystem_vendor"))),
                          _int(_read_text(os.path.join(devdir, "subsystem_device"))))
        link = os.path.join(devdir, "driver")
        self.driver = os.path.basename(os.readlink(link)) if os.path.islink(link) else (ue.get("DRIVER") or None)

    @property
    def display(self) -> bool:
        return self.cls is not None and (self.cls >> 8) in DISPLAY_CLASSES

    def describe(self) -> str:
        return "%s [%04x:%04x class 0x%06x%s]" % (self.bdf, self.vendor or 0, self.device or 0, self.cls or 0,
                                                 ", driver %s" % self.driver if self.driver else "")


def _pci_devices(host: Host) -> List[PciDevice]:
    root = host.path("bus", "pci", "devices")
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    return [PciDevice(os.path.join(root, n)) for n in names]


def select_device(host: Host, pci: Optional[str]) -> PciDevice:
    devices = _pci_devices(host)
    if pci:
        want = normalize_bdf(pci)
        found = [d for d in devices if d.bdf == want]
        if not found:
            raise RequirementError("--pci %s: no such PCI device under %s" % (want, host.path("bus", "pci",
                                                                                                "devices")))
        dev = found[0]
        if dev.vendor != NVIDIA:
            raise RequirementError("%s is not an NVIDIA device (vendor 0x%04x, NVIDIA is 0x10de): refusing to touch "
                                   "its BAR0" % (dev.bdf, dev.vendor or 0))
        if not dev.display:
            raise RequirementError("%s is NVIDIA but class 0x%06x is not a display controller (VGA 0x0300xx or 3D "
                                   "0x0302xx): it is another function of the card (audio, USB...); give the GPU "
                                   "function with --pci" % (dev.bdf, dev.cls or 0))
        return dev
    gpus = [d for d in devices if d.vendor == NVIDIA and d.display]
    if not gpus:
        wsl = "microsoft" in platform.release().lower()
        raise RequirementError("no NVIDIA display/3D controller under %s%s" % (
            host.path("bus", "pci", "devices"),
            " (WSL2 exposes no PCI device to Linux: run on bare-metal Linux)" if wsl else ""))
    if len(gpus) > 1:
        raise RequirementError("%d NVIDIA GPUs found; choose one with --pci: %s"
                               % (len(gpus), "; ".join(d.describe() for d in gpus)))
    return gpus[0]


def _lockdown(host: Host) -> str:
    text = _read_text(host.path("kernel", "security", "lockdown"))
    if text is None:
        return "unknown"
    m = re.search(r"\[(\w+)\]", text)
    return m.group(1) if m else "unknown"


def _config(dev: PciDevice) -> bytes:
    try:
        with open(os.path.join(dev.dir, "config"), "rb") as fh:
            return fh.read(4096)
    except OSError:
        return b""


def _pm_state(cfg: bytes) -> Optional[int]:
    """D-state from the PCI power-management capability's PMCSR bits 1:0 (PCI_CAP_ID_PM 0x01, PCI_PM_CTRL 4)."""
    if len(cfg) < 0x40 or not struct.unpack_from("<H", cfg, 0x06)[0] & 0x10:  # PCI_STATUS_CAP_LIST
        return None
    ptr, seen = cfg[0x34] & 0xFC, set()
    while ptr and ptr not in seen and ptr + 6 <= len(cfg):
        seen.add(ptr)
        if cfg[ptr] == 0x01:
            return struct.unpack_from("<H", cfg, ptr + 4)[0] & 0x3
        ptr = cfg[ptr + 1] & 0xFC
    return None


def check_preconditions(host: Host, args, warn) -> dict:
    """Refuse with a precise reason and a remedy, or return what was found (recorded in the metadata)."""
    if host.system != "Linux":
        raise RequirementError("the pramin method needs Linux (this is %s): it maps the GPU's BAR0 through sysfs "
                               "(/sys/bus/pci/devices/<bdf>/resource0). Boot the evidence machine into a Linux "
                               "examiner environment; WSL2 exposes no PCI device" % (host.system or "unknown"))
    if host.euid() != 0:
        raise RequirementError("the pramin method needs root (sysfs resource0 and the full PCI config space are "
                               "root-only): run it with sudo")
    lockdown = _lockdown(host)
    if lockdown not in ("none", "unknown"):
        raise RequirementError("kernel lockdown is active (%s: [%s]): it blocks user-space access to PCI BARs "
                               "(LOCKDOWN_PCI_ACCESS, mmap of resource0 fails with EPERM). Boot a kernel without "
                               "lockdown (with Secure Boot enforcing lockdown, disable Secure Boot for the examiner "
                               "boot)" % (host.path("kernel", "security", "lockdown"), lockdown))
    dev = select_device(host, getattr(args, "pci", None))
    info = {"bdf": dev.bdf, "vendor": "0x%04x" % NVIDIA, "device": "0x%04x" % (dev.device or 0),
            "class": "0x%06x" % (dev.cls or 0), "subsystem": "%04x:%04x" % tuple(x or 0 for x in dev.subsystem),
            "sysfs": dev.dir, "lockdown": lockdown, "driver": dev.driver, "driver_active": False}
    if lockdown == "unknown":
        warn("kernel lockdown state unknown (%s unreadable); an EPERM from mmap below would mean lockdown"
             % host.path("kernel", "security", "lockdown"))
    if dev.driver == "vfio-pci":
        info["vfio_passthrough"] = True
        warn("%s is bound to vfio-pci (VM passthrough): the guest's driver owns the PRAMIN window. The result is "
             "sound only while the VM is PAUSED for the whole acquisition (e.g. virsh suspend); a running guest "
             "can race the window and its driver can corrupt VRAM" % dev.bdf)
    elif dev.driver == "pci-stub":
        info["note"] = "pci-stub holds the device without using it"
    elif dev.driver:
        if not getattr(args, "allow_bound_driver", False):
            raise RequirementError(
                "driver %r is bound to %s and uses the PRAMIN window itself: it caches the window position and does "
                "not re-read it, so moving the window under it sends its own VRAM accesses to the wrong address "
                "(corruption or a GPU hang). Stop the display server and GPU users, then unbind it (echo %s > "
                "/sys/bus/pci/drivers/%s/unbind), or pass --allow-bound-driver to accept that risk"
                % (dev.driver, dev.bdf, dev.bdf, dev.driver))
        info["driver_active"] = True
        warn("--allow-bound-driver: driver %r is ACTIVE on %s. Keto will move the PRAMIN window under it: the "
             "driver's own PRAMIN accesses during the acquisition go to Keto's window position and can CORRUPT VRAM "
             "or hang the GPU; moves by the driver are detected and retried, but not all races are detectable. "
             "Recorded as driver_active=true" % (dev.driver, dev.bdf))
    cfg = _config(dev)
    if len(cfg) < 0x40:
        raise RequirementError("cannot read the PCI config space of %s (%d bytes from %s)"
                               % (dev.bdf, len(cfg), os.path.join(dev.dir, "config")))
    vendor_cfg = struct.unpack_from("<H", cfg, 0)[0]
    command = struct.unpack_from("<H", cfg, PCI_COMMAND)[0]
    if vendor_cfg == 0xFFFF:
        raise RequirementError("%s config space reads 0xffff: the device does not respond (D3cold or removed). "
                               "Wake it (runtime PM: echo on > %s) and retry"
                               % (dev.bdf, os.path.join(dev.dir, "power", "control")))
    state = _read_text(os.path.join(dev.dir, "power_state"))
    if state is None:
        pm = _pm_state(cfg)
        state = None if pm is None else "D%d" % pm
    if state is None:
        warn("power state of %s unknown (no power_state file, no PM capability); BOOT_0 is checked next" % dev.bdf)
        state = "unknown"
    elif state != "D0":
        raise RequirementError("%s is in power state %s, not D0: BAR0 is not accessible (reads return all-ones). "
                               "Wake it (runtime PM: echo on > %s) and retry"
                               % (dev.bdf, state, os.path.join(dev.dir, "power", "control")))
    if not command & PCI_COMMAND_MEMORY:
        raise RequirementError("PCI memory decoding is disabled on %s (COMMAND 0x%04x, bit 1 clear): BAR0 is not "
                               "decoded. Enable the device first (echo 1 > %s, or setpci -s %s COMMAND=0x2:0x2)"
                               % (dev.bdf, command, os.path.join(dev.dir, "enable"), dev.bdf))
    res = os.path.join(dev.dir, "resource0")
    try:
        bar0_size = os.stat(res).st_size
    except OSError as exc:
        raise RequirementError("%s has no readable BAR0 (%s: %s)" % (dev.bdf, res, exc))
    if bar0_size < APERTURE + APERTURE_SIZE:
        raise RequirementError("BAR0 of %s is 0x%x bytes: smaller than the end of the PRAMIN aperture (0x%x)"
                               % (dev.bdf, bar0_size, APERTURE + APERTURE_SIZE))
    info.update(power_state=state, command="0x%04x" % command, bar0={"path": res, "size": bar0_size})
    return info


def open_bar0(host: Host, info: dict):
    path, size = info["bar0"]["path"], info["bar0"]["size"]
    try:
        return host.open_bar0(path, size)
    except OSError as exc:
        e = exc.errno
        if e == errno.EPERM:
            why = ("EPERM: the kernel is locked down (LOCKDOWN_PCI_ACCESS) or a security module denies it; boot "
                   "without lockdown")
        elif e == errno.EINVAL:
            why = ("EINVAL: a driver has claimed BAR0 and the kernel treats claimed MMIO as exclusive "
                   "(CONFIG_IO_STRICT_DEVMEM=y, strict iomem checks: the default, or iomem=strict). Unbind the "
                   "driver (it releases the region), or boot with iomem=relaxed")
        elif e == errno.EACCES:
            why = "EACCES: run as root; check the file mode and SELinux/AppArmor policy"
        else:
            why = "%s" % exc
        raise RequirementError("mmap of %s refused (%s)" % (path, why))


def choose_vram_size(mmio, chip: Chip, host: Host, bdf: str, operator: Optional[int], warn) -> Tuple[int, str, dict]:
    """The cited register first, else NVML for this PCI device, else ``--vram-size``; refuse if none."""
    candidates = {}
    reg_size, reg_what = size_from_register(mmio, chip)
    candidates["register"] = {"bytes": reg_size, "detail": reg_what}
    nvml_size = None
    if reg_size is None:
        nv = host.nvml() or {}
        for d in nv.get("devices") or []:
            bus = d["pci"].get("bus_id") if isinstance(d.get("pci"), dict) else None
            try:
                same = isinstance(bus, str) and normalize_bdf(bus) == bdf  # NVML: "00000000:01:00.0"
            except RequirementError:
                same = False
            mem = d.get("memory")
            if same and isinstance(mem, dict) and isinstance(mem.get("total"), int) and mem["total"] > 0:
                nvml_size = mem["total"]
                candidates["nvml"] = {"bytes": nvml_size, "detail": "NVML memory.total of %s (%s)"
                                                                    % (bus, d.get("name"))}
                break
        else:
            candidates["nvml"] = {"bytes": None, "detail": "NVML unavailable or no device at %s" % bdf
                                  if not nv.get("devices") else "no NVML device at %s" % bdf}
    if operator:
        candidates["operator"] = {"bytes": operator, "detail": "--vram-size"}
    for key in ("register", "nvml", "operator"):
        c = candidates.get(key)
        if c and c["bytes"]:
            size, source = c["bytes"], "%s: %s" % (key, c["detail"])
            break
    else:
        raise RequirementError("VRAM size of %s (%s) unknown: %s; %s. Give it with --vram-size (e.g. 8G)"
                               % (chip.name, chip.generation, reg_what, candidates["nvml"]["detail"]))
    if operator and operator != size:
        warn("--vram-size 0x%x ignored: %s gives 0x%x (a cited register or NVML takes precedence)"
             % (operator, source.split(":")[0], size))
    return size, source, candidates


def plan_range(args, vram_size: int, window: WindowRegister) -> Tuple[int, int]:
    start = getattr(args, "start", None) or 0
    length = getattr(args, "length", None)
    if start < 0 or (length is not None and length <= 0):
        raise RequirementError("--start must be >= 0 and --length > 0")
    if start >= vram_size:
        raise RequirementError("--start 0x%x is at or beyond the VRAM size 0x%x" % (start, vram_size))
    end = vram_size if length is None else start + length
    start, end = start & ~(PAGE - 1), -(-end // PAGE) * PAGE  # whole 4 KiB pages
    if end > vram_size:
        raise RequirementError("--start/--length end 0x%x is beyond the VRAM size 0x%x: shorten --length"
                               % (end, vram_size))
    if end > window.max_vram:
        raise RequirementError("VRAM end 0x%x is beyond what %s BASE %s can address (0x%x)"
                               % (end, window.name, window.base_bits, window.max_vram))
    return start, end


# -- acquisition ---------------------------------------------------------------------------------------------------

def blocks(start: int, end: int):
    """``(window_base, vram_addr, length)``: each window position covers up to 1 MiB from its 64 KiB-aligned base,
    read in ``BLOCK`` pieces."""
    pos = start
    while pos < end:
        base = pos & ~(WINDOW_ALIGN - 1)
        limit = min(end, base + APERTURE_SIZE)
        while pos < limit:
            n = min(BLOCK, limit - pos)
            yield base, pos, n
            pos += n


def error_pages(data: bytes, addr: int):
    """``(page_address, {error words})`` for each 4 KiB page made only of PRI error words."""
    for i in range(0, len(data) - PAGE + 1, PAGE):
        if data[i + 3:i + PAGE:4] != _TOP_BA:
            continue
        words = set(struct.unpack_from("<%dI" % (PAGE // 4), data, i))
        if all(is_pri_error(w) for w in words):
            yield addr + i, words


def _add_range(ranges: list, start: int, size: int, **extra):
    if ranges and ranges[-1]["_end"] == start and all(ranges[-1].get(k) == v for k, v in extra.items()
                                                      if k != "words"):
        ranges[-1]["_end"] += size
        if "words" in extra:
            ranges[-1]["words"] |= extra["words"]
        return
    ranges.append(dict(extra, _start=start, _end=start + size))


def _ranges_out(ranges: list) -> list:
    out = []
    for r in ranges:
        d = {"start": "0x%x" % r["_start"], "size": r["_end"] - r["_start"]}
        for k, v in r.items():
            if not k.startswith("_"):
                d[k] = sorted("0x%08x" % w for w in v)[:8] if k == "words" else v
        out.append(d)
    return out


def _digests(data: bytes) -> bytes:
    return b"".join(hashlib.blake2b(data[i:i + PAGE], digest_size=8).digest() for i in range(0, len(data), PAGE))


def acquire_pramin(args, out, base_metadata, host: Optional[Host] = None) -> int:
    host = host if host is not None else default_host()
    warnings: List[str] = []

    def warn(msg):
        warnings.append(msg)
        host.err.write("WARNING: %s\n" % msg)

    if threading.current_thread() is not threading.main_thread():
        raise RequirementError("the pramin method must run in the main thread: the signal handlers that protect the "
                               "window restore can only be installed there")
    info = check_preconditions(host, args, warn)
    mmio = open_bar0(host, info)
    try:
        return _acquire(args, out, base_metadata, host, info, mmio, warn, warnings)
    finally:
        mmio.close()


def _acquire(args, out, meta, host, info, mmio, warn, warnings) -> int:
    chip = identify(mmio)
    window = chip.window
    if window.offset + 4 > info["bar0"]["size"] or (chip.size_register or 0) + 4 > info["bar0"]["size"]:
        raise RequirementError("BAR0 (0x%x bytes) does not contain the registers used for %s"
                               % (info["bar0"]["size"], chip.name))
    vram_size, size_source, candidates = choose_vram_size(mmio, chip, host, info["bdf"],
                                                          getattr(args, "vram_size", None), warn)
    start, end = plan_range(args, vram_size, window)
    passes = getattr(args, "passes", 1)
    if passes is None or passes < 1:
        raise RequirementError("--passes must be 1 or more")
    bulk = bool(getattr(args, "bulk_mmio", False))
    if bulk:
        warn("--bulk-mmio: aperture reads use memcpy, which may issue loads wider than 32 bits to BAR0 (not "
             "validated on hardware)")
    pr = {"pci": {k: info[k] for k in ("bdf", "vendor", "device", "class", "subsystem", "sysfs")},
          "driver": info["driver"], "driver_active": info["driver_active"],
          "allow_bound_driver": bool(getattr(args, "allow_bound_driver", False)),
          "lockdown": info["lockdown"], "power_state": info["power_state"], "pci_command": info["command"],
          "bar0": info["bar0"], "boot_0": "0x%08x" % chip.boot0,
          "boot_42": None if chip.boot42 is None else "0x%08x" % chip.boot42, "chipset": "0x%03x" % chip.chipset,
          "chip": chip.name, "architecture": chip.generation, "identification_notes": chip.notes,
          "window_register": window.as_dict(), "aperture": {"offset": "0x%x" % APERTURE, "size": APERTURE_SIZE},
          "vram_size": vram_size, "vram_size_source": size_source, "vram_size_candidates": candidates,
          "range": {"start": "0x%x" % start, "end": "0x%x" % end}, "mmio_access": "memcpy (--bulk-mmio)" if bulk
          else "aligned 32-bit loads", "block": BLOCK, "passes": passes, "zero_pages_omitted": False,
          "validation": "emulator only (keto.testing.fakebar0); not validated on real hardware"}
    for k in ("vfio_passthrough", "note"):
        if k in info:
            pr[k] = info[k]
    meta["device"] = {"name": "NVIDIA %s (identified from NV_PMC_BOOT_%s)" % (chip.name, "42" if chip.boot42
                                                                               is not None else "0"),
                      "chipset": "0x%03x" % chip.chipset, "architecture": chip.generation,
                      "pci_bus_id": info["bdf"], "pci_device_id": info["device"], "vram_size": vram_size,
                      "source": "BAR0 registers and sysfs of the acquiring machine"}
    meta["pramin"] = pr
    meta["acquisition"]["warnings"] = warnings
    writer = ContainerWriter(args.out, meta, exclusive=not getattr(args, "force", False))
    reader = None
    status = "complete"
    acquired: list = []
    errs: list = []
    changed: list = []
    error_count = 0
    stopped = None
    restored = None
    t0 = time.perf_counter()
    t_pass1 = None
    with _SignalGuard(host.err) as guard:
        try:
            reader = PraminReader(mmio, window, bulk, boot0=chip.boot0)
            digests = bytearray() if passes > 1 else None
            for p in range(1, passes + 1):
                di = 0
                for base, addr, n in blocks(start, end):
                    guard.check()
                    data = reader.read(base, addr, n)
                    if _ONES in data:  # RM's check: an all-ones read may mean the GPU is gone
                        reader.check_alive(addr)
                    if p == 1:
                        for pa, words in error_pages(data, addr):
                            error_count += 1
                            _add_range(errs, pa, PAGE, words=set(words))
                        writer.append("vram", addr, data)
                        _add_range(acquired, addr, n)
                        if digests is not None:
                            digests += _digests(data)
                    else:
                        now = _digests(data)
                        for j in range(0, len(now), 8):
                            if now[j:j + 8] != digests[di + j:di + j + 8]:
                                _add_range(changed, addr + j // 8 * PAGE, PAGE, **{"pass": p})
                        di += len(now)
                if p == 1:
                    t_pass1 = time.perf_counter() - t0
        except BaseException as exc:
            stopped = exc
            status = "incomplete: %s" % (exc if isinstance(exc, AcquisitionInterrupted)
                                         else "%s: %s" % (type(exc).__name__, exc))
            raise
        finally:
            if reader is not None:
                try:
                    restored = reader.restore()
                except Exception as exc:  # the container must still be closed and say so
                    restored = False
                    pr["window_restore_error"] = "%s: %s" % (type(exc).__name__, exc)
                pr.update(reader.metadata())
            if restored is False:
                warn("the PRAMIN window could NOT be restored: %s still reads %s (wanted %s). GPU state is "
                     "changed: do not rely on the driver; reboot the machine after the acquisition"
                     % (window.name, "0x%08x" % reader.after if reader.after is not None else "?",
                        "0x%08x" % reader.foreign))
            read_bytes = sum(r["_end"] - r["_start"] for r in acquired)
            pr["acquired_ranges"] = _ranges_out(acquired)
            pr["error_ranges"] = _ranges_out(errs)
            pr["error_pages"] = error_count
            pr["changed_ranges"] = _ranges_out(changed)
            pr["changed_pages"] = sum((r["_end"] - r["_start"]) // PAGE for r in changed)
            pr["seconds"] = round(time.perf_counter() - t0, 3)
            if t_pass1:
                pr["pass1_mib_per_s"] = round(read_bytes / t_pass1 / (1 << 20), 1)
            meta["acquisition"]["status"] = status
            meta["acquisition"]["notes"] = (
                "physical VRAM through the BAR0 PRAMIN window (%s at 0x%x, 1 MiB aperture at BAR0+0x%x) of %s %s "
                "(%s), %s; %d pass(es); all pages stored (zero pages included); %d page(s) of PRI error words; "
                "window saved, read back after every write, re-checked after every aperture read (%d move(s) by "
                "another agent) and %s; driver: %s; validated against an emulator only"
                % (window.name, window.offset, APERTURE, info["bdf"], chip.name, chip.generation, pr["mmio_access"],
                   passes, error_count, reader.moved + reader.moved_between if reader else 0,
                   "restored (verified)" if restored else "NOT restored" if restored is False else "never written",
                   "%s (ACTIVE)" % info["driver"] if info["driver_active"] else info["driver"] or "none"))
            writer.metadata = meta
            writer.close()
            if stopped is not None:
                out.write("partial container %s (%s); acquired %s\n" % (args.out, status, ", ".join(
                    "0x%x-0x%x" % (r["_start"], r["_end"]) for r in acquired) or "nothing"))
                out.write("evidence fingerprint: %s\n" % writer.fingerprint)
    from keto.acquire.cli import report_written
    out.write("pramin: %s %s (%s) at %s, %s: VRAM 0x%x-0x%x (%d MiB) in %d pass(es), %.1f MiB/s -> %s, %d "
              "segment(s); %d error page(s), %d changed page(s), %d window move(s) by others; window %s\n"
              % (chip.name, "0x%03x" % chip.chipset, chip.generation, info["bdf"], window.name, start, end,
                 (end - start) >> 20, passes, pr.get("pass1_mib_per_s", 0.0), args.out, len(writer.segments),
                 error_count, pr["changed_pages"], reader.moved + reader.moved_between,
                 "untouched" if reader.restored_to is None else "restored to 0x%08x (%s)" % (
                     reader.restored_to, "verified" if restored else "NOT verified")))
    report_written(out, writer)
    if restored is False:
        raise PraminError("the PRAMIN window could not be restored (see the warning above); the container is "
                          "written and records it")
    guard.check()  # a signal that arrived after the last read: honour it now that everything is closed
    return 0
