"""The Keto evidence container (``.keto``) and LiME host-memory images.

A ``.keto`` file bundles everything an acquisition produced so analysis is
reproducible and verifiable:

    header   (64 B)  magic "KETOEVD\\x01" (older containers: "VRMNCR\\0\\1", still read), version,
                     header size, segment-table offset/count,
                     flags, metadata offset/length, header digest (version 2)
    data             segment payloads, back to back
    metadata (JSON)  device identity, acquisition method/notes/time, per-segment SHA-256,
                     and an optional ``live_snapshot`` (recorded live-system state)
    segment table    32 B per segment: space id, flags, address, length, file offset

Integrity (version 2): the evidence *fingerprint* is the SHA-256 of the header fields (everything but the
magic and the digest), the metadata JSON and the segment table. Its first 16 bytes are stored in the header,
so any change to the metadata (which records every segment's SHA-256 and the SHA-256 of all data) or to the
segment table is detected when the container is opened. The full fingerprint is printed at acquisition;
recording it outside the container (case notes) also exposes a forgery that rewrites data and hashes together
(``verify --expected-fingerprint``). Version 1 containers carry no digest: their metadata is unprotected.

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

MAGIC = b"KETOEVD\x01"
LEGACY_MAGICS = (b"VRMNCR\x00\x01",)  # written before the project was renamed to Keto; still read
MAGICS = (MAGIC,) + LEGACY_MAGICS
HEADER = struct.Struct("<8sIIQIIQQ16s")
SEGMENT = struct.Struct("<IIQQQ")
SPACES = {0: "vram", 1: "sysmem", 2: "bar0", 3: "bar1", 4: "rom", 5: "residual", 6: "gpuva", 7: "process",
          8: "kbtf"}
SPACE_IDS = {v: k for k, v in SPACES.items()}
LIME_MAGIC = 0x4C694D45
LIME_HEADER = struct.Struct("<IIQQ8s")
VERSION = 2               # 2: header digest over header fields + metadata + segment table
DIGEST_SIZE = 16


def fingerprint(header: bytes, meta_blob: bytes, table: bytes) -> str:
    """Evidence fingerprint (hex SHA-256) over the header fields (bytes 8..48: everything but the magic and the
    digest), the metadata JSON and the segment table."""
    return hashlib.sha256(b"keto-fingerprint/1" + bytes(header[8:HEADER.size - DIGEST_SIZE]) + meta_blob
                          + table).hexdigest()


class Segment:
    __slots__ = ("space", "flags", "address", "length", "file_offset")

    def __init__(self, space, flags, address, length, file_offset):
        self.space, self.flags, self.address, self.length, self.file_offset = space, flags, address, length, file_offset

    @property
    def space_name(self):
        return SPACES.get(self.space, "space%d" % self.space)


class ContainerWriter:
    """Writes a ``.keto`` container. ``exclusive=True`` refuses to replace an existing file (evidence is never
    overwritten); the default replaces it (synthetic/test data)."""

    def __init__(self, path: str, metadata: Optional[dict] = None, exclusive: bool = False):
        self.path = path
        try:
            self.fh = open(path, "xb" if exclusive else "wb")
        except FileExistsError:
            raise FormatError("%s already exists: refusing to overwrite it" % path)
        self.fh.write(b"\x00" * HEADER.size)
        self.metadata = dict(metadata or {})
        self.segments: List[Segment] = []
        self.hashes: List[str] = []
        self._total = hashlib.sha256()
        self._open = None  # (segment, hash) still being extended by append()
        self.fingerprint: Optional[str] = None

    def _finish_open(self):
        if self._open is not None:
            seg, h = self._open
            self.segments.append(seg)
            self.hashes.append(h.hexdigest())
            self._open = None

    def add_segment(self, space: Union[str, int], address: int, data: Union[bytes, Iterable[bytes]],
                    flags: int = 0) -> Segment:
        self._finish_open()
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

    def append(self, space: Union[str, int], address: int, chunk: bytes) -> None:
        """Stream ``chunk`` at ``address``: it extends the previous appended segment when it continues it
        (same space, contiguous address), otherwise it starts a new segment. Memory use stays one chunk."""
        space_id = SPACE_IDS[space] if isinstance(space, str) else space
        chunk = bytes(chunk)
        if not chunk:
            return
        cur = self._open
        if cur is None or cur[0].space != space_id or cur[0].address + cur[0].length != address:
            self._finish_open()
            cur = self._open = (Segment(space_id, 0, address, 0, self.fh.tell()), hashlib.sha256())
        self.fh.write(chunk)
        cur[1].update(chunk)
        self._total.update(chunk)
        cur[0].length += len(chunk)

    def close(self):
        self._finish_open()
        meta = dict(self.metadata)
        meta["segments"] = [{"space": s.space_name, "address": s.address, "length": s.length, "sha256": h}
                            for s, h in zip(self.segments, self.hashes)]
        meta["data_sha256"] = self._total.hexdigest()
        blob = json.dumps(meta, indent=1, default=str).encode("utf-8")
        meta_off = self.fh.tell()
        self.fh.write(blob)
        seg_off = self.fh.tell()
        table = b"".join(SEGMENT.pack(s.space, s.flags, s.address, s.length, s.file_offset) for s in self.segments)
        self.fh.write(table)
        header = HEADER.pack(MAGIC, VERSION, HEADER.size, seg_off, len(self.segments), 0, meta_off, len(blob),
                             b"\x00" * DIGEST_SIZE)
        self.fingerprint = fingerprint(header, blob, table)
        self.fh.seek(0)
        self.fh.write(header[:HEADER.size - DIGEST_SIZE] + bytes.fromhex(self.fingerprint)[:DIGEST_SIZE])
        self.fh.close()


class Container:
    """Reads a ``.keto`` container. A container whose metadata or segment table cannot be read raises
    :class:`FormatError`; cheaper-to-detect damage (truncated segments, a header digest that no longer matches
    the metadata/segment table) is listed in ``problems`` so callers can warn before analysing it."""

    def __init__(self, path: str):
        self.path = path
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            raw = fh.read(HEADER.size)
            if len(raw) < HEADER.size or raw[:8] not in MAGICS:
                raise FormatError("not a Keto container (or its header is truncated): %s" % path)
            (_, self.version, hsize, seg_off, seg_count, self.flags, meta_off, meta_len,
             self.stored_digest) = HEADER.unpack(raw)
            if meta_off + meta_len > size or seg_off + SEGMENT.size * seg_count > size:
                raise FormatError("container %s is truncated or damaged: its metadata/segment table lies beyond "
                                  "the end of the file (%d bytes)" % (path, size))
            fh.seek(meta_off)
            self.meta_blob = fh.read(meta_len)
            fh.seek(seg_off)
            self.table = fh.read(SEGMENT.size * seg_count)
        try:
            self.metadata = json.loads(self.meta_blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FormatError("container %s has corrupt metadata (%s)" % (path, exc))
        if not isinstance(self.metadata, dict):
            raise FormatError("container %s has corrupt metadata (not an object)" % path)
        self.segments = [Segment(*SEGMENT.unpack_from(self.table, i * SEGMENT.size)) for i in range(seg_count)]
        self.fingerprint = fingerprint(raw, self.meta_blob, self.table)
        #: True/False for version-2 containers, None when no digest was recorded (version 1)
        self.digest_ok = (bytes.fromhex(self.fingerprint)[:DIGEST_SIZE] == self.stored_digest
                          if self.version >= 2 else None)
        self.problems: List[str] = []
        if self.digest_ok is False:
            self.problems.append("header digest does not match the metadata/segment table: the container was "
                                 "modified after acquisition")
        for i, s in enumerate(self.segments):
            if s.file_offset + s.length > size:
                self.problems.append("segment %d (%s @0x%x) extends beyond the end of the file: truncated"
                                     % (i, s.space_name, s.address))
        self._file: Optional[FileLayer] = None

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

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
        """Check everything the container records about itself. One row per segment (its SHA-256 against the
        metadata, and the segment-table entry against the metadata's address/length/space), then a
        ``metadata`` row (header digest over header fields, metadata and segment table; ``ok`` is None for
        version-1 containers, which carry no digest) and a ``data`` row (SHA-256 over all segment data against
        ``data_sha256``)."""
        out = []
        recorded = self.metadata.get("segments", [])
        if not isinstance(recorded, list):
            recorded = []
        total = hashlib.sha256()
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
                    total.update(chunk)
                    left -= len(chunk)
                rec = recorded[i] if i < len(recorded) and isinstance(recorded[i], dict) else {}
                expected = rec.get("sha256")
                notes = []
                if left:
                    notes.append("truncated: %d byte(s) missing" % left)
                if rec and (rec.get("address"), rec.get("length"), rec.get("space")) != (s.address, s.length,
                                                                                         s.space_name):
                    notes.append("segment table differs from metadata (%s @0x%x +%d recorded)" % (
                        rec.get("space"), rec.get("address") or 0, rec.get("length") or 0))
                if expected is None:
                    notes.append("no recorded hash")
                elif expected != h.hexdigest():
                    notes.append("SHA-256 mismatch")
                out.append({"segment": i, "space": s.space_name, "address": s.address, "length": s.length,
                            "sha256": h.hexdigest(), "expected": expected, "ok": not notes,
                            "detail": "; ".join(notes)})
        if len(recorded) != len(self.segments):
            out.append({"segment": -3, "space": "segment-table", "address": 0, "length": len(self.segments),
                        "sha256": "-", "expected": len(recorded), "ok": False,
                        "detail": "metadata records %d segment(s), the table holds %d" % (len(recorded),
                                                                                         len(self.segments))})
        detail = {True: "header digest matches", False: "header digest MISMATCH: metadata or segment table "
                  "modified", None: "version %d container: metadata is not integrity-protected" % self.version}
        out.append({"segment": -1, "space": "metadata", "address": 0, "length": len(self.meta_blob),
                    "sha256": self.fingerprint, "expected": self.stored_digest.hex() if self.version >= 2 else None,
                    "ok": self.digest_ok, "detail": detail[self.digest_ok]})
        recorded_total = self.metadata.get("data_sha256")
        out.append({"segment": -2, "space": "data", "address": 0, "length": sum(s.length for s in self.segments),
                    "sha256": total.hexdigest(), "expected": recorded_total,
                    "ok": recorded_total == total.hexdigest() if recorded_total else None,
                    "detail": ("data_sha256 matches" if recorded_total == total.hexdigest() else
                               "data_sha256 MISMATCH" if recorded_total else "no data_sha256 recorded")})
        return out


def is_container(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) in MAGICS
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
    try:
        while pos < size:
            if pos + LIME_HEADER.size > size:
                raise FormatError("LiME file %s is truncated: %d trailing byte(s) at file offset 0x%x are not a "
                                  "complete range header" % (path, size - pos, pos))
            magic, version, s_addr, e_addr, _ = LIME_HEADER.unpack(f.read(pos, LIME_HEADER.size))
            if magic != LIME_MAGIC or e_addr < s_addr:
                raise FormatError("bad LiME header at file offset 0x%x" % pos)
            length = e_addr - s_addr + 1
            if pos + LIME_HEADER.size + length > size:
                raise FormatError("LiME file %s is truncated: the range at file offset 0x%x needs %d bytes, %d "
                                  "remain" % (path, pos, length, size - pos - LIME_HEADER.size))
            segs.append((s_addr, length, f, pos + LIME_HEADER.size))
            pos += LIME_HEADER.size + length
    except Exception:
        f.close()
        raise
    return SegmentedLayer(name, segs)


def write_lime(path: str, ranges: Iterable[tuple]) -> None:
    """``ranges``: iterable of ``(start_address, data)``."""
    with open(path, "wb") as fh:
        for start, data in ranges:
            fh.write(LIME_HEADER.pack(LIME_MAGIC, 1, start, start + len(data) - 1, b"\x00" * 8))
            fh.write(data)
