"""Physical-memory image formats: detection and a single entry point that opens any of them as a layer addressed by
PHYSICAL address.

Formats (``detect`` names):

* ``windump``   - Windows kernel crash / live dumps, 64-bit ("PAGEDU64"): full, bitmap, live-kernel, RDMP (windump.py)
* ``elfcore``   - ELF cores with physical PT_LOADs: QEMU ``dump-guest-memory``, VirtualBox ``dumpvmcore`` (elfcore.py)
* ``vmware``    - VMware .vmss/.vmsn state files and their .vmem companions (vmware.py)
* ``hiber``     - Windows 8+ hiberfil.sys (hiber.py, codecs in xpress.py)
* ``lime``      - LiME (container.py)
* ``container`` - Keto evidence containers (container.py; ``open_memory_image`` returns its ``sysmem`` layer)
* ``None``      - anything else: a raw image (flat file, offset = physical address)

``open_memory_image`` returns ``(layer, metadata)``: absent pages raise ``InvalidAddressException`` like every other
layer and ``layer.ranges()`` lists what is present; ``metadata["format"]`` names the format, the other keys are the
format's facts in snake_case (addresses as ints), ``warnings`` lists anything the analyst must know.
"""

from __future__ import annotations

import bisect
import os
from typing import Iterable, List, Optional, Tuple

from keto.framework.exceptions import FormatError, RequirementError
from keto.framework.layers import DataLayer, FileLayer, SegmentedLayer

PAGE = 0x1000
#: formats Context opens through this module (LiME and containers keep their own code paths there)
PHYSICAL_FORMATS = ("windump", "elfcore", "vmware", "hiber")
FORMATS = PHYSICAL_FORMATS + ("lime", "container")


class PhysicalRunLayer(SegmentedLayer):
    """Physical address space backed by runs of one or more files: ``runs`` are ``(address, length, file_layer,
    file_offset)``. Unlike the base class it caches the range starts, so reads stay O(log n) on dumps with many
    thousands of runs, and reads a run's bytes straight from the file mapping."""

    KIND = "physical"

    def __init__(self, name: str, runs: List[Tuple[int, int, FileLayer, int]], kind: Optional[str] = None,
                 files: Tuple[FileLayer, ...] = ()):
        super().__init__(name, (r for r in runs if r[1] > 0))
        self._files = files  # closed with the layer even when no run refers to them (a fully truncated image)
        if kind:
            self.KIND = kind
        self._range_starts = [s for s, _ in self._ranges]
        prev_end = -1
        for addr, length, _b, _o in self.segments:
            if addr < prev_end:
                raise FormatError("%s: physical runs overlap at 0x%x" % (name, addr))
            prev_end = addr + length

    def _starts(self):
        return self._ranges, self._range_starts

    def _read_run(self, offset, length):
        segs = self.segments
        i = bisect.bisect_right(self._seg_starts, offset) - 1
        addr, slen, base, boff = segs[i]
        if offset + length <= addr + slen:  # the common case: one segment
            return base._read_run(boff + offset - addr, length)
        out = bytearray()
        pos, end = offset, offset + length
        while pos < end:
            addr, slen, base, boff = segs[i]
            take = min(end, addr + slen) - pos
            out += base._read_run(boff + pos - addr, take)
            pos += take
            i += 1
        return bytes(out)

    def close(self):
        super().close()
        for f in self._files:
            f.close()


def file_runs(name: str, path: str, runs: Iterable[Tuple[int, int, int]], kind: str,
              file_layer: Optional[FileLayer] = None) -> Tuple[PhysicalRunLayer, List[str]]:
    """Build a PhysicalRunLayer from ``(address, length, file_offset)`` runs inside ``path``. Runs reaching past the
    end of the file are clipped (page granular) and reported in the returned warnings instead of failing: a
    truncated copy of a dump is still evidence."""
    f = file_layer or FileLayer(name + "-file", path)
    size = f.length + f.base_offset if f._mm is not None else 0
    out, warnings, missing = [], [], 0
    for addr, length, off in runs:
        if length <= 0:
            continue
        avail = max(0, min(length, size - off))
        avail -= avail % PAGE if avail < length else 0
        if avail < length:
            missing += length - avail
        if avail > 0:
            out.append((addr, avail, f, off))
    if missing:
        warnings.append("file is truncated: %d byte(s) (%d page(s)) the format describes lie beyond the end of %s "
                        "(%d bytes) and are absent" % (missing, (missing + PAGE - 1) // PAGE, path, size))
    try:
        return PhysicalRunLayer(name, out, kind, files=(f,) if file_layer is None else ()), warnings
    except Exception:
        if file_layer is None:
            f.close()
        raise


# -- detection --------------------------------------------------------------------------------------------------------
def _head(path: str, n: int = 0x2040) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def detect(path: str) -> Optional[str]:
    """The image format of ``path`` (see module docstring), or None for a raw image. Every positive answer needs a
    signature plus structural checks, so raw VRAM/RAM images (which can contain anything) are not misdetected."""
    from keto.formats import container, elfcore, hiber, vmware, windump
    head = _head(path)
    if len(head) >= 8 and head[:8] in container.MAGICS:
        return "container"
    if len(head) >= container.LIME_HEADER.size:
        magic, version, s_addr, e_addr, _ = container.LIME_HEADER.unpack_from(head)
        if magic == container.LIME_MAGIC and version >= 1 and e_addr >= s_addr:
            return "lime"
    if windump.looks_like(head):
        return "windump"
    if hiber.looks_like(head):
        return "hiber"
    if vmware.looks_like_state(head, path) or vmware.looks_like_vmem(path):
        return "vmware"
    if elfcore.looks_like(head, os.path.getsize(path) if os.path.exists(path) else 0):
        return "elfcore"
    return None


def open_memory_image(name: str, path: str) -> Tuple[DataLayer, dict]:
    """Open ``path`` as a physical-address layer named ``name``; see the module docstring for the metadata."""
    if not os.path.isfile(path):
        raise RequirementError("memory image not found: %s" % path)
    fmt = detect(path)
    if fmt == "windump":
        from keto.formats.windump import open_windump
        return open_windump(name, path)
    if fmt == "elfcore":
        from keto.formats.elfcore import open_elfcore
        return open_elfcore(name, path)
    if fmt == "vmware":
        from keto.formats.vmware import open_vmware
        return open_vmware(name, path)
    if fmt == "hiber":
        from keto.formats.hiber import open_hiber
        return open_hiber(name, path)
    if fmt == "lime":
        from keto.formats.container import open_lime
        layer = open_lime(name, path)
        return layer, {"format": "lime", "ranges": len(layer.ranges()), "warnings": []}
    if fmt == "container":
        from keto.formats.container import Container
        cont = Container(path)
        layers = cont.layers()
        if "sysmem" not in layers:
            cont.close()
            raise RequirementError("container %s has no sysmem (host physical memory) segments" % path)
        layer = layers["sysmem"]
        layer.name = name
        return layer, {"format": "container", "warnings": list(cont.problems), "container_metadata": cont.metadata}
    layer = FileLayer(name, path)
    return layer, {"format": "raw", "warnings": []}

