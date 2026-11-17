"""Scanners: sweep a layer for byte patterns, chunk by chunk, with overlap.

The scanning model mirrors Volatility 3: a scanner is a callable that receives a
chunk of data and its absolute offset and yields ``(offset, value)`` hits. The
driver (``scan``) handles chunking, overlaps and de-duplication so individual
scanners stay trivial. All heavy lifting is done by ``bytes.find`` / ``re``,
which run in C, so multi-gigabyte VRAM images scan at disk speed.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable, Iterator, Optional, Sequence, Tuple

from keto.framework.layers import CHUNK_SIZE, DataLayer


class Scanner:
    #: bytes of look-ahead needed so matches spanning chunks are not lost
    overlap = 0
    #: only report hits whose offset is a multiple of this
    alignment = 1

    def __call__(self, data: bytes, data_offset: int) -> Iterator[Tuple[int, object]]:
        raise NotImplementedError


class BytesScanner(Scanner):
    def __init__(self, needle: bytes, alignment: int = 1):
        self.needle = needle
        self.overlap = len(needle) - 1
        self.alignment = alignment

    def __call__(self, data, data_offset):
        find = data.find
        pos = find(self.needle)
        while pos != -1:
            yield data_offset + pos, self.needle
            pos = find(self.needle, pos + 1)


class RegexScanner(Scanner):
    def __init__(self, pattern, flags: int = 0, max_length: int = 4096, alignment: int = 1):
        self.regex = re.compile(pattern, flags) if isinstance(pattern, (bytes, str)) else pattern
        self.overlap = max_length
        self.alignment = alignment

    def __call__(self, data, data_offset):
        for m in self.regex.finditer(data):
            yield data_offset + m.start(), m


class MultiStringScanner(RegexScanner):
    """Find any of several literal byte strings in one pass."""

    def __init__(self, needles: Sequence[bytes], flags: int = 0):
        needles = sorted(set(needles), key=len, reverse=True)
        pattern = b"|".join(re.escape(n) for n in needles)
        super().__init__(pattern, flags, max_length=max(len(n) for n in needles))


class AnchoredScanner(Scanner):
    """Find cheap literal anchors with ``bytes.find`` (C speed, ~1.5 GB/s each) and
    run the expensive regex only in a window around each anchor. Python's ``re``
    does not optimise alternations or case-insensitive literals, so scanning a
    multi-gigabyte image with one big regex is orders of magnitude slower.

    With ``regex=None`` each anchor hit is reported as ``(offset, anchor)``.
    """

    def __init__(self, anchors: Sequence[bytes], regex=None, before: int = 0, after: int = 512,
                 ignore_case: bool = False):
        self.ignore_case = ignore_case
        self.anchors = sorted({a.lower() if ignore_case else a for a in anchors}, key=len, reverse=True)
        self.regex = re.compile(regex, re.DOTALL) if isinstance(regex, bytes) else regex
        self.before, self.after = before, after
        self.overlap = before + after + max(len(a) for a in self.anchors)

    def __call__(self, data, data_offset):
        hay = bytes(data).lower() if self.ignore_case else data
        reported = set()
        for a in self.anchors:
            pos = hay.find(a)
            while pos != -1:
                if self.regex is None:
                    if pos not in reported:
                        reported.add(pos)
                        yield data_offset + pos, a
                else:
                    lo = max(0, pos - self.before)
                    m = self.regex.search(data, lo, min(len(data), pos + len(a) + self.after))
                    if m and m.start() <= pos < max(m.end(), pos + 1) and m.start() not in reported:
                        reported.add(m.start())
                        yield data_offset + m.start(), m
                pos = hay.find(a, pos + 1)


def scan(layer: DataLayer, scanner: Scanner, chunk_size: int = CHUNK_SIZE,
         start: Optional[int] = None, end: Optional[int] = None,
         progress: Optional[Callable[[int, int], None]] = None) -> Iterator[Tuple[int, object]]:
    """Run ``scanner`` across ``layer`` and yield de-duplicated hits."""
    total = layer.size or 1
    done = 0
    for off, data, payload in layer.iter_chunks(chunk_size, scanner.overlap, start, end):
        limit = off + payload
        for hit_off, value in scanner(data, off):
            if hit_off >= limit:
                continue
            if scanner.alignment > 1 and hit_off % scanner.alignment:
                continue
            yield hit_off, value
        done += payload
        if progress:
            progress(done, total)


def scan_aligned_u32(layer: DataLayer, field_offset: int, stride: int, predicate: Callable[[int], bool],
                     chunk_size: int = CHUNK_SIZE) -> Iterator[Tuple[int, int]]:
    """Check one little-endian u32 at ``base + field_offset`` for every
    ``stride``-aligned base address; yield ``(base, value)`` where ``predicate``
    holds. Uses ``memoryview.cast`` striding, so a 6 GiB image with a 4 KiB
    stride is ~1.5M checks done mostly in C."""
    assert field_offset % 4 == 0 and stride % 4 == 0
    chunk_size = max(stride, chunk_size - chunk_size % stride)
    for off, data, payload in layer.iter_chunks(chunk_size, 0):
        # align the chunk start to the stride
        skew = (-off) % stride
        usable = (payload - skew) - (payload - skew) % stride
        if usable <= 0:
            continue
        mv = memoryview(data)[skew:skew + usable].cast("I")
        words = mv[field_offset // 4::stride // 4]
        for idx, value in enumerate(words):
            if predicate(value):
                yield off + skew + idx * stride, value


def first_hits(hits: Iterable, limit: int):
    for i, h in enumerate(hits):
        if i >= limit:
            break
        yield h
