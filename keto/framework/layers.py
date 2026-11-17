"""Data layers (address spaces), the Keto equivalent of Volatility's layers.

* ``FileLayer``      - a raw file, memory-mapped read-only (a flat VRAM dump).
* ``BytesLayer``     - an in-memory buffer (tests, extracted blobs).
* ``SegmentedLayer`` - a sparse address space built from (address, length) runs
                       that live inside another layer (container / LiME segments).
* ``GmmuLayer``      - a GPU virtual address space translated through NVIDIA
                       GMMU page tables (see ``keto.gpu.gmmu``).

Every layer exposes the same small interface so scanners and plugins never care
which kind of address space they are looking at.
"""

from __future__ import annotations

import bisect
import mmap
import os
import struct
from typing import Iterator, List, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException

CHUNK_SIZE = 16 * 1024 * 1024


class DataLayer:
    """Abstract base class for an address space."""

    #: short human description of the layer kind
    KIND = "abstract"

    def __init__(self, name: str):
        self.name = name

    # --- required interface -------------------------------------------------
    def ranges(self) -> List[Tuple[int, int]]:
        """Sorted list of ``(start, length)`` runs that are readable."""
        raise NotImplementedError

    def _read_run(self, offset: int, length: int) -> bytes:
        """Read inside a single valid run (no validity checks)."""
        raise NotImplementedError

    # --- derived helpers -----------------------------------------------------
    @property
    def minimum_address(self) -> int:
        r = self.ranges()
        return r[0][0] if r else 0

    @property
    def maximum_address(self) -> int:
        r = self.ranges()
        return (r[-1][0] + r[-1][1] - 1) if r else 0

    @property
    def size(self) -> int:
        """Total number of readable bytes."""
        return sum(length for _, length in self.ranges())

    def _starts(self):
        rs = self.ranges()
        return rs, [s for s, _ in rs]

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if offset < 0 or length <= 0:
            return False
        rs, starts = self._starts()
        i = bisect.bisect_right(starts, offset) - 1
        while i >= 0 and i < len(rs):
            start, rlen = rs[i]
            if not (start <= offset < start + rlen):
                return False
            take = min(length, start + rlen - offset)
            length -= take
            offset += take
            if length == 0:
                return True
            i += 1
        return False

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Read ``length`` bytes; gaps raise ``InvalidAddressException`` unless ``pad``."""
        if length <= 0:
            return b""
        rs, starts = self._starts()
        out = bytearray()
        pos = offset
        end = offset + length
        i = max(bisect.bisect_right(starts, pos) - 1, 0)
        while pos < end:
            while i < len(rs) and rs[i][0] + rs[i][1] <= pos:
                i += 1
            if i < len(rs) and rs[i][0] <= pos:
                start, rlen = rs[i]
                take = min(end, start + rlen) - pos
                out += self._read_run(pos, take)
                pos += take
                continue
            # gap
            nxt = rs[i][0] if i < len(rs) else end
            gap = min(nxt, end) - pos
            if not pad:
                raise InvalidAddressException(self.name, pos)
            out += b"\x00" * gap
            pos += gap
        return bytes(out)

    def read_struct(self, fmt: str, offset: int):
        s = struct.Struct(fmt)
        return s.unpack(self.read(offset, s.size))

    def u32(self, offset: int) -> int:
        return struct.unpack("<I", self.read(offset, 4))[0]

    def u64(self, offset: int) -> int:
        return struct.unpack("<Q", self.read(offset, 8))[0]

    def iter_chunks(self, chunk_size: int = CHUNK_SIZE, overlap: int = 0,
                    start: Optional[int] = None, end: Optional[int] = None
                    ) -> Iterator[Tuple[int, bytes, int]]:
        """Yield ``(offset, data, payload_len)`` over every readable run.

        ``data`` may extend ``overlap`` bytes past the payload so scanners can
        match across chunk boundaries; only matches starting inside the first
        ``payload_len`` bytes should be reported.
        """
        for rstart, rlen in self.ranges():
            rend = rstart + rlen
            s = rstart if start is None else max(rstart, start)
            e = rend if end is None else min(rend, end)
            pos = s
            while pos < e:
                payload = min(chunk_size, e - pos)
                take = min(payload + overlap, rend - pos)
                yield pos, self._read_run(pos, take), payload
                pos += payload

    def describe(self) -> str:
        return "%s (%s, %d run(s), %d bytes)" % (self.name, self.KIND, len(self.ranges()), self.size)


class FileLayer(DataLayer):
    """A raw file mapped read-only. Offsets are file offsets."""

    KIND = "file"

    def __init__(self, name: str, path: str, base_offset: int = 0, length: Optional[int] = None):
        super().__init__(name)
        self.path = os.path.abspath(path)
        self._fh = open(self.path, "rb")
        file_size = os.fstat(self._fh.fileno()).st_size
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ) if file_size else None
        self.base_offset = base_offset
        self.length = (file_size - base_offset) if length is None else length
        self._ranges = [(0, self.length)] if self.length > 0 else []

    def ranges(self):
        return self._ranges

    def _read_run(self, offset, length):
        o = self.base_offset + offset
        return self._mm[o:o + length]

    def raw(self):
        """The underlying mmap (supports the buffer protocol, usable with ``re``)."""
        return self._mm

    def close(self):
        if self._mm is not None and not self._mm.closed:
            self._mm.close()
        self._fh.close()


class BytesLayer(DataLayer):
    """An in-memory layer."""

    KIND = "bytes"

    def __init__(self, name: str, data: bytes, base: int = 0):
        super().__init__(name)
        self.data = bytes(data)
        self.base = base
        self._ranges = [(base, len(self.data))] if self.data else []

    def ranges(self):
        return self._ranges

    def _read_run(self, offset, length):
        o = offset - self.base
        return self.data[o:o + length]


class SegmentedLayer(DataLayer):
    """A sparse layer: each segment maps ``[address, address+length)`` onto
    ``base_layer`` at ``base_offset``. Used for container and LiME images."""

    KIND = "segmented"

    def __init__(self, name: str, segments: List[Tuple[int, int, DataLayer, int]]):
        super().__init__(name)
        self.segments = sorted(segments, key=lambda s: s[0])
        self._ranges = []
        for addr, length, _, _ in self.segments:
            if self._ranges and self._ranges[-1][0] + self._ranges[-1][1] == addr:
                self._ranges[-1] = (self._ranges[-1][0], self._ranges[-1][1] + length)
            else:
                self._ranges.append((addr, length))
        self._seg_starts = [s[0] for s in self.segments]

    def ranges(self):
        return self._ranges

    def _read_run(self, offset, length):
        out = bytearray()
        pos, end = offset, offset + length
        i = bisect.bisect_right(self._seg_starts, pos) - 1
        while pos < end:
            addr, slen, base, boff = self.segments[i]
            if pos >= addr + slen:
                i += 1
                continue
            take = min(end, addr + slen) - pos
            out += base.read(boff + (pos - addr), take)
            pos += take
            i += 1
        return bytes(out)

    def translate(self, offset: int) -> Optional[Tuple[DataLayer, int]]:
        i = bisect.bisect_right(self._seg_starts, offset) - 1
        if i >= 0:
            addr, slen, base, boff = self.segments[i]
            if addr <= offset < addr + slen:
                return base, boff + (offset - addr)
        return None

    def close(self):
        for base in {id(s[2]): s[2] for s in self.segments}.values():
            if hasattr(base, "close"):
                base.close()
