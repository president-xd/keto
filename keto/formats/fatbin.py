"""CUDA fat binaries: the container nvcc embeds in host executables/libraries.

Layout (as documented by the open-source ``cricket`` CUDA RPC project and
consistent with what nvcc emits)::

    __nv_fatbinwrap  { u32 magic 0x466243B1; u32 version; u64 data; u64 filename_or_fatbins }
    fatbin header    { u32 magic 0xBA55ED50; u16 version; u16 header_size; u64 size }
    entry header     { u16 kind (1 PTX, 2 ELF); u16 version; u32 header_size; u64 size;
                       u32 compressed_size; u32 unknown; u16 minor; u16 major; u32 arch;
                       u32 obj_name_offset; u32 obj_name_len; u64 flags; u64 zero;
                       u64 decompressed_size }
    flags: 0x1 64-bit, 0x2 debug, 0x10 linux, 0x1000 deflate-, 0x2000 LZ4-, 0x8000 zstd-compressed payload
           (compression flags per ZLUDA FatbinFileHeaderFlags; LZ4 also per cricket FATBIN_FLAG_COMPRESS)
"""

from __future__ import annotations

import struct
import zlib
from typing import List, Optional

from keto.formats import compression, lz4

FATBIN_MAGIC = 0xBA55ED50
FATBIN_MAGIC_BYTES = struct.pack("<I", FATBIN_MAGIC)
WRAPPER_MAGIC = 0x466243B1
WRAPPER_MAGIC_BYTES = struct.pack("<I", WRAPPER_MAGIC)
KIND_PTX, KIND_ELF = 1, 2
KIND_NAMES = {KIND_PTX: "PTX", KIND_ELF: "ELF"}
FLAG_64BIT, FLAG_DEBUG, FLAG_LINUX, FLAG_COMPRESS = 0x1, 0x2, 0x10, 0x2000
FLAG_DEFLATE, FLAG_ZSTD = 0x1000, 0x8000
CODECS = ((FLAG_COMPRESS, "lz4"), (FLAG_ZSTD, "zstd"), (FLAG_DEFLATE, "deflate"))
ENTRY_FMT = "<HHIQIIHHIIIQQQ"
ENTRY_SIZE = struct.calcsize(ENTRY_FMT)  # 64
#: no fatbin entry decompresses to more than this (hostile entries are cut off here, not allocated)
MAX_ENTRY_SIZE = 512 << 20


class FatbinEntry:
    def __init__(self, offset, fields, payload: bytes):
        (self.kind, self.version, self.header_size, self.size, self.compressed_size, self.unknown,
         self.minor, self.major, self.arch, self.obj_name_offset, self.obj_name_len, self.flags, self.zero,
         self.decompressed_size) = fields
        self.offset = offset
        self.payload = payload
        self.error: Optional[str] = None
        self._data: Optional[bytes] = None

    @property
    def kind_name(self):
        return KIND_NAMES.get(self.kind, "kind%d" % self.kind)

    @property
    def compression(self) -> Optional[str]:
        """"lz4", "zstd", "deflate" or None."""
        return next((name for flag, name in CODECS if self.flags & flag), None)

    @property
    def compressed(self):
        return self.compression is not None

    @property
    def size_limit(self) -> int:
        """Largest decompressed size accepted: the declared size when the header has one, else MAX_ENTRY_SIZE."""
        return min(self.decompressed_size, MAX_ENTRY_SIZE) if self.decompressed_size else MAX_ENTRY_SIZE

    @property
    def data(self) -> Optional[bytes]:
        """Decompressed payload (None if decompression failed or no decoder is available; ``error`` says why).
        Output is bounded by :attr:`size_limit`, so a hostile entry cannot exhaust memory."""
        if self._data is None and self.error is None:
            codec = self.compression
            limit = self.size_limit
            if self.decompressed_size > MAX_ENTRY_SIZE:
                self.error = "declared decompressed size %d exceeds the %d-byte limit" % (self.decompressed_size,
                                                                                          MAX_ENTRY_SIZE)
            elif codec is None:
                self._data = self.payload
            elif codec == "lz4":
                try:
                    self._data = lz4.decompress(self.payload, max_size=limit,
                                                expected_size=self.decompressed_size or 0)
                except lz4.LZ4Error as exc:
                    self.error = "decompression failed: %s" % exc
            elif codec == "zstd":
                if not compression.zstd_available():
                    self.error = "zstd entry: no zstd decoder (Python 3.14+ or the 'zstandard' package)"
                else:
                    got = compression.zstd_frame(self.payload, max_output=limit)
                    if got is None:
                        self.error = "decompression failed: not a complete zstd frame of at most %d bytes" % limit
                    else:
                        self._data = got[0]
            else:
                for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 31):  # zlib-wrapped, raw deflate, gzip
                    try:
                        d = zlib.decompressobj(wbits)
                        out = d.decompress(self.payload, limit + 1)
                    except zlib.error:
                        continue
                    if len(out) > limit:
                        self.error = "decompression failed: output exceeds %d bytes" % limit
                    else:
                        self._data = out
                    break
                else:
                    self.error = "decompression failed: not a deflate stream"
        return self._data


class Fatbin:
    def __init__(self, offset: int, version: int, header_size: int, size: int, entries: List[FatbinEntry]):
        self.offset, self.version, self.header_size, self.size, self.entries = offset, version, header_size, size, entries

    @property
    def total_size(self):
        return self.header_size + self.size


def parse_fatbin(data: bytes, offset: int = 0) -> Optional[Fatbin]:
    """Parse a fatbin whose header starts at ``data[0]``."""
    if len(data) < 16:
        return None
    magic, version, hsize, size = struct.unpack_from("<IHHQ", data)
    if magic != FATBIN_MAGIC or hsize < 16 or hsize > 256 or size == 0 or size > (1 << 31):
        return None
    entries = []
    pos = hsize
    end = min(hsize + size, len(data))
    while pos + ENTRY_SIZE <= end:
        fields = struct.unpack_from(ENTRY_FMT, data, pos)
        kind, _, ehsize, esize = fields[0], fields[1], fields[2], fields[3]
        if kind not in (KIND_PTX, KIND_ELF) or ehsize < ENTRY_SIZE or ehsize > 4096 or esize > (1 << 31):
            break
        payload = data[pos + ehsize:pos + ehsize + esize]
        entries.append(FatbinEntry(offset + pos, fields, payload))
        pos += ehsize + esize
    if not entries:
        return None
    return Fatbin(offset, version, hsize, size, entries)


def parse_wrapper(data: bytes) -> Optional[dict]:
    if len(data) < 24:
        return None
    magic, version, ptr, fname = struct.unpack_from("<IIQQ", data)
    if magic != WRAPPER_MAGIC or version not in (1, 2):
        return None
    return {"version": version, "data_ptr": ptr, "filename_or_fatbins": fname}


def build_fatbin(entries) -> bytes:
    """``entries``: iterable of ``(kind, arch, payload, compress)`` where ``compress`` is False, True (LZ4),
    "lz4", "zstd" or "deflate". Returns header + entries."""
    body = bytearray()
    for kind, arch, payload, compress in entries:
        codec = "lz4" if compress is True else (compress or None)
        if codec == "lz4":
            raw = lz4.compress(payload)
        elif codec == "zstd":
            raw = compression.zstd_compress(payload)
        elif codec == "deflate":
            raw = zlib.compress(payload, 9)
        else:
            raw = payload
        raw += b"\x00" * (-len(raw) % 8)
        flags = FLAG_64BIT | FLAG_LINUX | next((f for f, n in CODECS if n == codec), 0)
        body += struct.pack(ENTRY_FMT, kind, 0x0101, ENTRY_SIZE, len(raw), len(raw) if compress else 0, 0,
                            0, 0, arch, 0, 0, flags, 0, len(payload) if compress else 0)
        body += raw
    return struct.pack("<IHHQ", FATBIN_MAGIC, 1, 16, len(body)) + bytes(body)
