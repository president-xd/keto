"""The Keto evidence container (``.keto``) and LiME host-memory images.

A ``.keto`` file bundles everything an acquisition produced so analysis is
reproducible and verifiable:

    header   (64 B)  magic "VRMNCR\\0\\1", version, header size, segment-table offset/count,
                     flags, metadata offset/length
    data             segment payloads, back to back
    metadata (JSON)  device identity, acquisition method/notes/time, per-segment SHA-256,
                     and an optional ``live_snapshot`` (recorded live-system state)
    segment table    32 B per segment: space id, flags, address, length, file offset

Address spaces: 0 vram (physical), 1 sysmem (host physical), 2 bar0, 3 bar1,
4 rom, 5 residual (CUDA allocations, keyed by GPU VA), 6 gpuva, 7 process (keyed by
process VA), 8 kbtf (the imaged kernel's BTF blob, host-RAM containers).
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Dict, Iterable, List, Optional, Union

from keto.framework.exceptions import FormatError
from keto.framework.layers import DataLayer, FileLayer, SegmentedLayer

MAGIC = b"VRMNCR\x00\x01"
HEADER = struct.Struct("<8sIIQIIQQ16s")
SEGMENT = struct.Struct("<IIQQQ")
SPACES = {0: "vram", 1: "sysmem", 2: "bar0", 3: "bar1", 4: "rom", 5: "residual", 6: "gpuva", 7: "process",
          8: "kbtf"}
SPACE_IDS = {v: k for k, v in SPACES.items()}
LIME_MAGIC = 0x4C694D45
LIME_HEADER = struct.Struct("<IIQQ8s")


class Segment:
    __slots__ = ("space", "flags", "address", "length", "file_offset")

    def __init__(self, space, flags, address, length, file_offset):
        self.space, self.flags, self.address, self.length, self.file_offset = space, flags, address, length, file_offset

    @property
    def space_name(self):
        return SPACES.get(self.space, "space%d" % self.space)


class ContainerWriter:
    def __init__(self, path: str, metadata: Optional[dict] = None):
        self.path = path
        self.fh = open(path, "wb")
        self.fh.write(b"\x00" * HEADER.size)
        self.metadata = dict(metadata or {})
        self.segments: List[Segment] = []
        self.hashes: List[str] = []
        self._total = hashlib.sha256()

    def add_segment(self, space: Union[str, int], address: int, data: Union[bytes, Iterable[bytes]],
                    flags: int = 0) -> Segment:
        space_id = SPACE_IDS[space] if isinstance(space, str) else space
        offset = self.fh.tell()
        h = hashlib.sha256()
        length = 0
        chunks = [data] if isinstance(data, (bytes, bytearray, memoryview)) else data
        for chunk in chunks:
            chunk = bytes(chunk)
            self.fh.write(chunk)
            h.update(chunk)
            self._total.update(chunk)
            length += len(chunk)
        seg = Segment(space_id, flags, address, length, offset)
        self.segments.append(seg)
        self.hashes.append(h.hexdigest())
        return seg

    def close(self):
        meta = dict(self.metadata)
        meta["segments"] = [{"space": s.space_name, "address": s.address, "length": s.length, "sha256": h}
                            for s, h in zip(self.segments, self.hashes)]
        meta["data_sha256"] = self._total.hexdigest()
        blob = json.dumps(meta, indent=1, default=str).encode("utf-8")
        meta_off = self.fh.tell()
        self.fh.write(blob)
        seg_off = self.fh.tell()
        for s in self.segments:
            self.fh.write(SEGMENT.pack(s.space, s.flags, s.address, s.length, s.file_offset))
        self.fh.seek(0)
        self.fh.write(HEADER.pack(MAGIC, 1, HEADER.size, seg_off, len(self.segments), 0, meta_off, len(blob),
                                  b"\x00" * 16))
        self.fh.close()


class Container:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            raw = fh.read(HEADER.size)
            if len(raw) < HEADER.size or raw[:8] != MAGIC:
                raise FormatError("not a Keto container")
            (_, self.version, hsize, seg_off, seg_count, self.flags, meta_off, meta_len,
             _) = HEADER.unpack(raw)
            fh.seek(meta_off)
            self.metadata = json.loads(fh.read(meta_len).decode("utf-8"))
            fh.seek(seg_off)
            table = fh.read(SEGMENT.size * seg_count)
        self.segments = [Segment(*SEGMENT.unpack_from(table, i * SEGMENT.size)) for i in range(seg_count)]
        self._file: Optional[FileLayer] = None

    def file_layer(self) -> FileLayer:
        if self._file is None:
            self._file = FileLayer("container-file", self.path)
        return self._file

    def layers(self) -> Dict[str, DataLayer]:
        by_space: Dict[str, list] = {}
        f = self.file_layer()
        for s in self.segments:
            if s.length:
                by_space.setdefault(s.space_name, []).append((s.address, s.length, f, s.file_offset))
        return {name: SegmentedLayer(name, segs) for name, segs in by_space.items()}

    def verify(self) -> List[dict]:
        """Recompute SHA-256 of every segment and compare with the metadata."""
        out = []
        recorded = self.metadata.get("segments", [])
        with open(self.path, "rb") as fh:
            for i, s in enumerate(self.segments):
                fh.seek(s.file_offset)
                h = hashlib.sha256()
                left = s.length
                while left:
                    chunk = fh.read(min(left, 1 << 22))
                    if not chunk:
                        break
                    h.update(chunk)
                    left -= len(chunk)
                expected = recorded[i]["sha256"] if i < len(recorded) else None
                out.append({"segment": i, "space": s.space_name, "address": s.address, "length": s.length,
                            "sha256": h.hexdigest(), "expected": expected, "ok": expected == h.hexdigest()})
        return out


def is_container(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == MAGIC
    except OSError:
        return False


def is_lime(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4)
        return len(raw) == 4 and struct.unpack("<I", raw)[0] == LIME_MAGIC
    except OSError:
        return False


def open_lime(name: str, path: str) -> SegmentedLayer:
    f = FileLayer(name + "-file", path)
    segs = []
    pos, size = 0, os.path.getsize(path)
    while pos + LIME_HEADER.size <= size:
        magic, version, s_addr, e_addr, _ = LIME_HEADER.unpack(f.read(pos, LIME_HEADER.size))
        if magic != LIME_MAGIC or e_addr < s_addr:
            raise FormatError("bad LiME header at file offset 0x%x" % pos)
        length = e_addr - s_addr + 1
        segs.append((s_addr, length, f, pos + LIME_HEADER.size))
        pos += LIME_HEADER.size + length
    return SegmentedLayer(name, segs)


def write_lime(path: str, ranges: Iterable[tuple]) -> None:
    """``ranges``: iterable of ``(start_address, data)``."""
    with open(path, "wb") as fh:
        for start, data in ranges:
            fh.write(LIME_HEADER.pack(LIME_MAGIC, 1, start, start + len(data) - 1, b"\x00" * 8))
            fh.write(data)
