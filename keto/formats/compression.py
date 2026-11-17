"""Decompression back-ends for GPU code containers.

* LZ4 block: pure Python (``formats.lz4``), always available.
* Zstandard: NVIDIA drivers ship internal GPU code in zstd frames (observed in
  libcuda.so 592.xx: ``28 B5 2F FD`` frames that decompress to cubins). Uses the
  standard library ``compression.zstd`` (Python 3.14+) or the ``zstandard``
  package when installed; otherwise reports that the decoder is unavailable
  instead of failing.
"""

from __future__ import annotations

import re
from typing import Iterator, Optional, Tuple

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _zstd_backend():
    try:
        from compression import zstd  # Python 3.14+
        return "stdlib", zstd
    except ImportError:
        pass
    try:
        import zstandard  # optional dependency
        return "zstandard", zstandard
    except ImportError:
        return None, None


BACKEND, _ZSTD = _zstd_backend()


def zstd_available() -> bool:
    return _ZSTD is not None


def zstd_frame(data: bytes, max_output: int = 256 << 20) -> Optional[Tuple[bytes, int]]:
    """Decompress the zstd frame at ``data[0]``; return ``(output, consumed_bytes)`` or None."""
    if _ZSTD is None or not data.startswith(ZSTD_MAGIC):
        return None
    try:
        if BACKEND == "stdlib":
            d = _ZSTD.ZstdDecompressor()
            out = d.decompress(data, max_length=max_output)
            if not d.eof:
                return None
            return out, len(data) - len(d.unused_data)
        dobj = _ZSTD.ZstdDecompressor().decompressobj()
        out = dobj.decompress(data)
        if len(out) > max_output:
            out = out[:max_output]
        return out, len(data) - len(dobj.unused_data)
    except Exception:
        return None


def zstd_compress(data: bytes) -> bytes:
    """Compress ``data`` into one zstd frame (test-data builder; needs a zstd back-end)."""
    if BACKEND == "stdlib":
        return _ZSTD.compress(data)
    if BACKEND == "zstandard":
        return _ZSTD.ZstdCompressor().compress(data)
    raise RuntimeError("no zstd back-end (Python 3.14+ or the 'zstandard' package)")


def iter_zstd_frames(data: bytes, base: int = 0, max_output: int = 256 << 20) -> Iterator[Tuple[int, int, bytes]]:
    """Yield ``(offset, compressed_size, decompressed)`` for every decodable zstd frame."""
    if _ZSTD is None:
        return
    for m in re.finditer(re.escape(ZSTD_MAGIC), data):
        r = zstd_frame(data[m.start():], max_output)
        if r:
            yield base + m.start(), r[1], r[0]


def status() -> str:
    return "zstd via %s" % BACKEND if BACKEND else "zstd unavailable (Python < 3.14 without the 'zstandard' package)"
