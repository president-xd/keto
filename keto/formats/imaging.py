"""Image helpers: a dependency-free PNG writer and NVIDIA block-linear (GOB) de-tiling.

Block-linear layout (Fermi and later, also documented by Tegra/Switch emulator
projects): a GOB is 64 bytes x 8 rows (512 B); a block is ``block_height``
GOBs stacked vertically; blocks are laid out left-to-right then top-to-bottom.
Inside a GOB the byte at (x, y) lives at::

    ((x % 64) // 32) * 256 + ((y % 8) // 2) * 64 + ((x % 32) // 16) * 32 + (y % 2) * 16 + (x % 16)
"""

from __future__ import annotations

import struct
import zlib
from typing import Optional

GOB_W, GOB_H, GOB_SIZE = 64, 8, 512


def write_png(path: str, width: int, height: int, pixels: bytes, channels: int = 4) -> None:
    """Write 8-bit RGB (channels=3) or RGBA (channels=4) pixels, row-major."""
    stride = width * channels
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw += pixels[y * stride:(y + 1) * stride].ljust(stride, b"\x00")

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    color = 6 if channels == 4 else 2
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b"")
    with open(path, "wb") as fh:
        fh.write(png)


def bgra_to_rgba(data: bytes, force_alpha: bool = True) -> bytes:
    out = bytearray(data)
    out[0::4], out[2::4] = data[2::4], data[0::4]
    if force_alpha:
        out[3::4] = b"\xff" * (len(out) // 4)
    return bytes(out)


def gob_offset(x: int, y: int) -> int:
    return ((x % 64) // 32) * 256 + ((y % 8) // 2) * 64 + ((x % 32) // 16) * 32 + (y % 2) * 16 + (x % 16)


def surface_size(width_bytes: int, height: int, block_height: int) -> int:
    gobs_x = -(-width_bytes // GOB_W)
    rows = -(-height // (GOB_H * block_height))
    return gobs_x * rows * GOB_SIZE * block_height


def _swizzled(x: int, y: int, gobs_x: int, block_height: int) -> int:
    block_bytes = GOB_SIZE * block_height
    return ((y // (GOB_H * block_height)) * block_bytes * gobs_x + (x // GOB_W) * block_bytes
            + ((y % (GOB_H * block_height)) // GOB_H) * GOB_SIZE + gob_offset(x, y))


def deswizzle(data: bytes, width_bytes: int, height: int, block_height: int) -> bytes:
    """Block-linear -> pitch-linear (``width_bytes`` per row, multiple of 16)."""
    gobs_x = -(-width_bytes // GOB_W)
    out = bytearray(width_bytes * height)
    mv = memoryview(data)
    n = len(data)
    for y in range(height):
        row = y * width_bytes
        for x in range(0, width_bytes, 16):
            src = _swizzled(x, y, gobs_x, block_height)
            if src + 16 <= n:
                out[row + x:row + x + 16] = mv[src:src + 16]
    return bytes(out)


def swizzle(linear: bytes, width_bytes: int, height: int, block_height: int) -> bytes:
    """Pitch-linear -> block-linear (used to build synthetic test surfaces)."""
    gobs_x = -(-width_bytes // GOB_W)
    out = bytearray(surface_size(width_bytes, height, block_height))
    for y in range(height):
        row = y * width_bytes
        for x in range(0, width_bytes, 16):
            dst = _swizzled(x, y, gobs_x, block_height)
            out[dst:dst + 16] = linear[row + x:row + x + 16]
    return bytes(out)


def smoothness(pixels: bytes, width_px: int, rows: int = 32, bpp: int = 4, start_row: int = 0) -> float:
    """Mean absolute vertical difference of the first colour channel (lower = more image-like)."""
    stride = width_px * bpp
    total = count = 0
    max_rows = len(pixels) // stride - 1
    step = max(1, width_px // 64)
    for y in range(start_row, min(start_row + rows, max_rows)):
        a = y * stride
        b = a + stride
        for x in range(0, stride, bpp * step):
            total += abs(pixels[a + x] - pixels[b + x]) + abs(pixels[a + x + 1] - pixels[b + x + 1])
            count += 2
    return total / count if count else 255.0


def horizontal_smoothness(pixels: bytes, bpp: int = 4, samples: int = 4096) -> float:
    total = count = 0
    limit = min(len(pixels) - bpp, samples * bpp)
    for i in range(0, limit, bpp):
        total += abs(pixels[i] - pixels[i + bpp])
        count += 1
    return total / count if count else 255.0


_Q4 = bytes(b >> 4 for b in range(256))


def autocorr_width(pixels: bytes, bpp: int = 4, min_w: int = 16, max_w: int = 8192, window: int = 6144
                   ) -> Optional[int]:
    """Row width (pixels) by autocorrelation: the shift at which the colour bytes best repeat themselves.

    Colour channels (alpha dropped) are quantised to 4 bits; for every candidate width the fraction of equal
    bytes between the stream and itself shifted by one row is computed with one big-integer XOR (C speed). The
    best width must stand out from the median score, and when a divisor of it (w/2, w/3 ...) scores almost as
    well the divisor is the real row width (2w, 3w ... repeat too)."""
    colour = bytes(b for i, b in enumerate(pixels[:bpp * (max_w * 2 + window)]) if i % bpp != bpp - 1)
    q = colour.translate(_Q4)
    cpp = bpp - 1
    n = window * cpp
    if len(q) < min_w * cpp + n:
        return None
    base = int.from_bytes(q[:n], "little")
    scores = {}
    for w in range(min_w, max_w + 1):
        off = w * cpp
        if off + n > len(q):
            break
        x = (base ^ int.from_bytes(q[off:off + n], "little")).to_bytes(n, "little")
        scores[w] = x.count(0) / n
    if not scores:
        return None
    ranked = sorted(scores.values())
    median = ranked[len(ranked) // 2]
    best = max(scores, key=lambda w: (scores[w], -w))
    if scores[best] - median < 0.12:
        return None  # flat or noisy region: no row structure
    for k in range(8, 1, -1):  # prefer the fundamental over its multiples
        if best % k == 0 and best // k >= min_w and scores.get(best // k, 0) >= scores[best] - 0.02:
            return best // k
    return best


def guess_width(pixels: bytes, candidates=None, bpp: int = 4) -> Optional[int]:
    """Row width in pixels: autocorrelation first (any integer width 16..8192); when it finds no clear row
    structure, the width (multiple of 16, 64..4096) whose vertical neighbours are most similar."""
    if candidates is None:
        w = autocorr_width(pixels, bpp)
        if w:
            return w
    candidates = candidates or [w for w in range(64, 4097, 16)]
    best, best_score = None, None
    for w in candidates:
        if len(pixels) < w * bpp * 8:
            continue
        s = smoothness(pixels, w, rows=8)
        if best_score is None or s < best_score - 0.01:
            best, best_score = w, s
    return best
