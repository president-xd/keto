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


def zstd_frame(data, max_output: int = 256 << 20) -> Optional[Tuple[bytes, int]]:
    """Decompress the zstd frame at ``data[0]`` (bytes or memoryview); return ``(output, consumed_bytes)``, or
    None when it is not a complete frame or would decompress to more than ``max_output`` bytes. Memory and time
    stay bounded by ``max_output`` (decompression bombs stop at the limit)."""
    if _ZSTD is None or bytes(data[:4]) != ZSTD_MAGIC:
        return None
    try:
        mv = memoryview(data)
        if BACKEND == "stdlib":
            # fed in slices: unused_data would otherwise copy everything after the frame for every candidate
            d = _ZSTD.ZstdDecompressor()
            out, n, pos = [], 0, 0
            while not d.eof:
                if d.needs_input:
                    if pos >= len(mv):
                        return None
                    piece = bytes(mv[pos:pos + (64 << 10)])
                    pos += len(piece)
                else:
                    piece = b""
                chunk = d.decompress(piece, max_length=max_output - n + 1)
                n += len(chunk)
                if n > max_output:
                    return None
                out.append(chunk)
            return b"".join(out), pos - len(d.unused_data)
        # python-zstandard: decompressobj().decompress() of a whole frame has no output limit and is quadratic
        # with the default write size, so the frame is fed in small slices and stopped at max_output
        dobj = _ZSTD.ZstdDecompressor().decompressobj(write_size=1 << 20)
        out, n, pos = [], 0, 0
        while pos < len(mv) and not dobj.eof:
            piece = bytes(mv[pos:pos + 1024])
            pos += len(piece)
            chunk = dobj.decompress(piece)
            n += len(chunk)
            if n > max_output:
                return None
            out.append(chunk)
        if not dobj.eof:
            return None
        return b"".join(out), pos - len(dobj.unused_data)
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
    """Yield ``(offset, compressed_size, decompressed)`` for every decodable zstd frame (no copy of ``data`` per
    candidate; each frame bounded by ``max_output``)."""
    if _ZSTD is None:
        return
    mv = memoryview(data)
    for m in re.finditer(re.escape(ZSTD_MAGIC), data):
        r = zstd_frame(mv[m.start():], max_output)
        if r:
            yield base + m.start(), r[1], r[0]


def status() -> str:
    return "zstd via %s" % BACKEND if BACKEND else "zstd unavailable (Python < 3.14 without the 'zstandard' package)"
