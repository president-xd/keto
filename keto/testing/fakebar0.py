"""An emulated NVIDIA BAR0 and a fake sysfs tree, for testing ``keto acquire --method pramin`` without hardware.

``FakeBar0`` implements the MMIO interface ``keto.acquire.pramin`` reads through (``size``, ``read32``,
``write32``, ``read_words``, ``read_bulk``, ``close``) with the semantics given in
docs/research/NVIDIA_HW_FACTS.md Topic 7:

* NV_PMC_BOOT_0 (0x0) and, from Pascal on, NV_PMC_BOOT_42 (0xa00) for a chosen chipset;
* the chip's VRAM-size register: NV_PFB_PRI_MMU_LOCAL_MEMORY_RANGE (0x100ce0) on Turing and GA100,
  NV_USABLE_FB_SIZE_IN_MB (0x1183a4) on GA102 and later;
* the window register of the chip's architecture: NV_PBUS_BAR0_WINDOW (0x1700: BASE 23:0, TARGET 25:24) up to
  Ada, NV_XAL_EP_BAR0_WINDOW (0x10fd40: BASE only, 21:0 / 22:0 / 30:0) on Hopper / Blackwell / Rubin; bits
  outside the fields read as zero;
* the 1 MiB PRAMIN aperture at 0x700000 over a VRAM buffer, at ``(BASE << 16) + offset``;
* injected PRI-error regions (VRAM ranges that read as an error word);
* a ``ConcurrentDriver`` that moves the window at chosen aperture reads, as a bound driver does;
* a "lost" mode (the GPU falls off the bus after N aperture reads: every read returns 0xffffffff);
* a log of every register access and aperture read, for asserting the window discipline.

It is strict where the code under test must be: unaligned or out-of-BAR accesses raise ``ValueError``, an aperture
read crossing the aperture end, a write to anything but the window register, or a write to the window register of
another architecture raise ``AssertionError``. Registers it does not implement read as 0xbadf1100 (envytools: "no
target for given address"); VRAM beyond the buffer and non-VRAM window targets read as 0xbad0fb00 (envytools
bad0fbXX "problem accessing memory"; what real hardware returns there is not documented: an emulator choice).

``make_sysfs`` writes a sysfs-like directory tree (PCI devices with vendor/device/class/uevent/config/power_state/
resource0, an optional driver link, and the lockdown file) so the precondition checks run against real files.
"""

from __future__ import annotations

import os
import struct
from typing import Callable, Dict, Iterable, List, Optional, Tuple

APERTURE, APERTURE_SIZE = 0x700000, 0x100000
BOOT_0, BOOT_42 = 0x0, 0xA00
PBUS_BAR0_WINDOW, XAL_EP_BAR0_WINDOW = 0x1700, 0x10FD40
LOCAL_MEMORY_RANGE, USABLE_FB_SIZE_IN_MB = 0x100CE0, 0x1183A4
NO_TARGET, UNBACKED, ALL_ONES = 0xBADF1100, 0xBAD0FB00, 0xFFFFFFFF


def window_layout(chipset: int) -> Tuple[int, int, bool]:
    """``(register offset, BASE field width in bits, has a TARGET field)`` for a chipset."""
    arch = chipset >> 4
    if arch == 0x18:
        return XAL_EP_BAR0_WINDOW, 22, False
    if arch in (0x1A, 0x1B):
        return XAL_EP_BAR0_WINDOW, 23, False
    if arch == 0x1C:
        return XAL_EP_BAR0_WINDOW, 31, False
    return PBUS_BAR0_WINDOW, 24, True


def size_register(chipset: int) -> Optional[int]:
    if (chipset >> 4) == 0x16 or chipset == 0x170:
        return LOCAL_MEMORY_RANGE
    if chipset >= 0x172:
        return USABLE_FB_SIZE_IN_MB
    return None


def encode_local_memory_range(size: int, ecc: bool = False) -> int:
    """LOWER_MAG (9:4) << (LOWER_SCALE (3:0) + 20) == size; ECC_MODE bit 30."""
    mag, scale = size >> 20, 0
    if mag << 20 != size or not mag:
        raise ValueError("size must be a non-zero multiple of 1 MiB")
    while mag > 63:
        if mag & 1:
            raise ValueError("0x%x cannot be encoded in LOWER_MAG/LOWER_SCALE" % size)
        mag, scale = mag >> 1, scale + 1
    return (mag << 4) | scale | (0x40000000 if ecc else 0)


class ConcurrentDriver:
    """A driver that writes the window register itself (nouveau and RM rewrite it whenever their cached position
    differs from the one they need). ``at``: aperture-read indexes at which it points the window at ``base`` just
    before that read is served; ``from_read``: it does so before every aperture read from that index on (a driver
    that keeps using PRAMIN); ``restore``: it puts the previous value back right after the read, a move no register
    check can see."""

    def __init__(self, base: int, at: Iterable[int] = (), from_read: Optional[int] = None, restore: bool = False):
        self.base, self.at, self.from_read, self.restore = base, set(at), from_read, restore
        self.writes: List[int] = []

    def fires(self, index: int) -> bool:
        return index in self.at or (self.from_read is not None and index >= self.from_read)


class FakeBar0:
    def __init__(self, vram: bytes, chipset: int = 0x197, size: int = 16 << 20, window: int = 0,
                 boot0: Optional[int] = None, boot42: Optional[int] = None, size_value: Optional[int] = None,
                 regs: Optional[Dict[int, int]] = None, error_regions: Iterable[Tuple[int, int, int]] = (),
                 driver: Optional[ConcurrentDriver] = None, window_writable: bool = True,
                 lose_after: Optional[int] = None, on_aperture_read: Optional[Callable[[int], None]] = None):
        self.vram = vram
        self.chipset = chipset
        self.size = size
        self.window_reg, bits, self.has_target = window_layout(chipset)
        self.base_mask = (1 << bits) - 1
        self.field_mask = self.base_mask | (0x3 << 24 if self.has_target else 0)
        self.window_raw = window & self.field_mask
        self.boot0 = boot0 if boot0 is not None else (chipset << 20) | 0xA1
        self.boot42 = boot42 if boot42 is not None else ((chipset << 20) | 0x10000 if chipset >= 0x130
                                                         else NO_TARGET)
        self.regs: Dict[int, int] = {BOOT_0: self.boot0, BOOT_42: self.boot42}
        sreg = size_register(chipset)
        if sreg == LOCAL_MEMORY_RANGE:
            self.regs[sreg] = size_value if size_value is not None else encode_local_memory_range(len(vram))
        elif sreg == USABLE_FB_SIZE_IN_MB:
            self.regs[sreg] = size_value if size_value is not None else len(vram) >> 20
        self.regs.update(regs or {})
        self.error_regions = [(s, e, w) for s, e, w in error_regions]
        self.driver = driver
        self.window_writable = window_writable
        self.lose_after = lose_after
        self.on_aperture_read = on_aperture_read
        self.lost = False
        self.closed = False
        self.opens = 1
        self.aperture_reads = 0
        self.bulk_reads = 0
        self.max_vram_end = 0
        self.log: List[tuple] = []

    # -- MMIO interface --------------------------------------------------------------------------------------------
    def _check(self, offset: int, length: int):
        if self.closed:
            raise ValueError("BAR0 mapping is closed")
        if offset % 4 or length % 4 or length <= 0 or offset < 0 or offset + length > self.size:
            raise ValueError("MMIO access 0x%x+0x%x is unaligned or outside BAR0 (0x%x bytes)"
                             % (offset, length, self.size))

    def read32(self, offset: int) -> int:
        self._check(offset, 4)
        if self.lost:
            v = ALL_ONES
        elif APERTURE <= offset < APERTURE + APERTURE_SIZE:
            return struct.unpack("<I", self._aperture(offset - APERTURE, 4))[0]
        elif offset == self.window_reg:
            v = self.window_raw
        else:
            v = self.regs.get(offset, NO_TARGET)
        self.log.append(("r32", offset, v))
        return v

    def write32(self, offset: int, value: int) -> None:
        self._check(offset, 4)
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("0x%x does not fit a 32-bit register" % value)
        self.log.append(("w32", offset, value))
        if offset in (PBUS_BAR0_WINDOW, XAL_EP_BAR0_WINDOW) and offset != self.window_reg:
            raise AssertionError("0x%x is not the window register of chipset 0x%x (0x%x is)"
                                 % (offset, self.chipset, self.window_reg))
        if offset != self.window_reg:
            raise AssertionError("pramin must write only the window register, not BAR0+0x%x" % offset)
        if self.lost or not self.window_writable:
            return
        self.window_raw = value & self.field_mask

    def read_words(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        if APERTURE <= offset < APERTURE + APERTURE_SIZE:
            if offset + length > APERTURE + APERTURE_SIZE:
                raise AssertionError("aperture read 0x%x+0x%x crosses the end of the PRAMIN aperture"
                                     % (offset, length))
            return self._aperture(offset - APERTURE, length)
        return b"".join(struct.pack("<I", self.read32(o)) for o in range(offset, offset + length, 4))

    def read_bulk(self, offset: int, length: int) -> bytes:
        self.bulk_reads += 1
        return self.read_words(offset, length)

    def close(self):
        self.closed = True

    def reopen(self) -> "FakeBar0":
        """Map the same device again (a new open of resource0): registers and VRAM keep their state."""
        self.closed = False
        self.opens += 1
        return self

    # -- emulation -------------------------------------------------------------------------------------------------
    def window_base(self) -> int:
        return (self.window_raw & self.base_mask) << 16

    def driver_value(self, base: int) -> int:
        return (base >> 16) & self.base_mask  # TARGET VID_MEM

    def _aperture(self, off: int, n: int) -> bytes:
        index = self.aperture_reads
        self.aperture_reads += 1
        if self.lose_after is not None and index >= self.lose_after:
            self.lost = True
        if self.on_aperture_read is not None:
            self.on_aperture_read(index)
        if self.lost:
            self.log.append(("ap", None, n, None))
            return b"\xff" * n
        saved = None
        if self.driver is not None and self.driver.fires(index):
            saved = self.window_raw
            self.window_raw = self.driver_value(self.driver.base)
            self.driver.writes.append(self.window_raw)
        target = (self.window_raw >> 24) & 3 if self.has_target else 0
        addr = self.window_base() + off
        self.log.append(("ap", addr, n, self.window_raw))
        if target:
            data = struct.pack("<I", UNBACKED) * (n // 4)
        else:
            data = bytes(self.vram[addr:addr + n])
            if len(data) < n:
                data += struct.pack("<I", UNBACKED) * ((n - len(data)) // 4)
            self.max_vram_end = max(self.max_vram_end, addr + n)
            for s, e, w in self.error_regions:
                lo, hi = max(s, addr), min(e, addr + n)
                if lo < hi:
                    buf = bytearray(data)
                    buf[lo - addr:hi - addr] = struct.pack("<I", w) * ((hi - lo) // 4)
                    data = bytes(buf)
        if saved is not None and self.driver.restore:
            self.window_raw = saved
        return data

    def window_writes(self) -> List[int]:
        return [v for op, off, v, *_ in self.log if op == "w32" and off == self.window_reg]


# -- fake sysfs ----------------------------------------------------------------------------------------------------

def pci_device(bdf: str = "0000:01:00.0", vendor: int = 0x10DE, device: int = 0x28A1, cls: int = 0x030000,
               driver: Optional[str] = None, power_state: Optional[str] = "D0", command: int = 0x0007,
               bar0_size: int = 16 << 20, pm_state: int = 0, subsystem: Tuple[int, int] = (0x10DE, 0x0000)) -> dict:
    return dict(bdf=bdf, vendor=vendor, device=device, cls=cls, driver=driver, power_state=power_state,
                command=command, bar0_size=bar0_size, pm_state=pm_state, subsystem=subsystem)


def _config_space(d: dict) -> bytes:
    cfg = bytearray(256)
    struct.pack_into("<HHHH", cfg, 0, d["vendor"], d["device"], d["command"], 0x0010)  # STATUS: CAP_LIST
    cfg[0x08] = 0xA1
    cfg[0x09:0x0C] = bytes((d["cls"] & 0xFF, (d["cls"] >> 8) & 0xFF, (d["cls"] >> 16) & 0xFF))
    struct.pack_into("<HH", cfg, 0x2C, *d["subsystem"])
    cfg[0x34] = 0x60
    struct.pack_into("<BBHH", cfg, 0x60, 0x01, 0x00, 0x0003, d["pm_state"] & 3)  # PM cap: ID, next, PMC, PMCSR
    return bytes(cfg)


def make_sysfs(root: str, devices: Iterable[dict] = (), lockdown: Optional[str] = "[none] integrity confidentiality"
               ) -> Dict[str, str]:
    """Write ``kernel/security/lockdown`` (unless ``lockdown`` is None) and one ``bus/pci/devices/<slot>`` directory
    per ``pci_device()`` dict under ``root``; returns ``{bdf: device directory}``. Device directories are named after
    the PCI address on POSIX and with ``_`` for ``:`` on Windows (NTFS forbids ``:``); ``uevent`` carries the real
    ``PCI_SLOT_NAME``, as the kernel's does. The ``driver`` link is a symlink where the OS allows one, and
    ``uevent`` always carries ``DRIVER=``."""
    if lockdown is not None:
        os.makedirs(os.path.join(root, "kernel", "security"), exist_ok=True)
        with open(os.path.join(root, "kernel", "security", "lockdown"), "w") as fh:
            fh.write(lockdown + "\n")
    out = {}
    base = os.path.join(root, "bus", "pci", "devices")
    os.makedirs(base, exist_ok=True)
    for d in devices:
        name = d["bdf"].replace(":", "_") if os.name == "nt" else d["bdf"]
        dev = os.path.join(base, name)
        os.makedirs(dev, exist_ok=True)
        files = {"vendor": "0x%04x" % d["vendor"], "device": "0x%04x" % d["device"], "class": "0x%06x" % d["cls"],
                 "subsystem_vendor": "0x%04x" % d["subsystem"][0], "subsystem_device": "0x%04x" % d["subsystem"][1],
                 "enable": "1"}
        uevent = ["PCI_CLASS=%X" % d["cls"], "PCI_ID=%04X:%04X" % (d["vendor"], d["device"]),
                  "PCI_SLOT_NAME=%s" % d["bdf"]]
        if d["driver"]:
            uevent.insert(0, "DRIVER=%s" % d["driver"])
            drv = os.path.join(root, "bus", "pci", "drivers", d["driver"])
            os.makedirs(drv, exist_ok=True)
            try:
                os.symlink(drv, os.path.join(dev, "driver"))
            except (OSError, NotImplementedError):
                pass  # e.g. Windows without the symlink privilege: uevent carries DRIVER=
        files["uevent"] = "\n".join(uevent)
        if d["power_state"] is not None:
            files["power_state"] = d["power_state"]
        for k, v in files.items():
            with open(os.path.join(dev, k), "w") as fh:
                fh.write(v + "\n")
        with open(os.path.join(dev, "config"), "wb") as fh:
            fh.write(_config_space(d))
        with open(os.path.join(dev, "resource0"), "wb") as fh:
            fh.truncate(d["bar0_size"])
        out[d["bdf"]] = dev
    return out


def poke(path: str, offset: int, data: bytes) -> None:
    """Write ``data`` at ``offset`` of a file (e.g. register values into a file standing in for resource0)."""
    with open(path, "r+b") as fh:
        fh.seek(offset)
        fh.write(data)
