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

    #: scanners that can search a buffer in place (``bytes.find``/``mmap.find`` and ``re`` with start/end bounds)
    #: implement ``scan_region(buf, start, end, base)``; ``scan`` then searches file mappings without copying
    scan_region = None


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

    def scan_region(self, buf, start, end, base):
        pos = buf.find(self.needle, start, end)
        while pos != -1:
            yield base + pos - start, self.needle
            pos = buf.find(self.needle, pos + 1, end)


class RegexScanner(Scanner):
    def __init__(self, pattern, flags: int = 0, max_length: int = 4096, alignment: int = 1):
        self.regex = re.compile(pattern, flags) if isinstance(pattern, (bytes, str)) else pattern
        self.overlap = max_length
        self.alignment = alignment

    def __call__(self, data, data_offset):
        for m in self.regex.finditer(data):
            yield data_offset + m.start(), m

    def scan_region(self, buf, start, end, base):
        for m in self.regex.finditer(buf, start, end):
            yield base + m.start() - start, m


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

    # Hits are collected per call and returned in offset order (one pass per anchor would otherwise yield them
    # anchor by anchor, so the order would depend on how the image was split into chunks or worker parts).
    def __call__(self, data, data_offset):
        hay = bytes(data).lower() if self.ignore_case else data
        reported = {}
        for a in self.anchors:
            pos = hay.find(a)
            while pos != -1:
                if self.regex is None:
                    reported.setdefault(pos, a)
                else:
                    lo = max(0, pos - self.before)
                    m = self.regex.search(data, lo, min(len(data), pos + len(a) + self.after))
                    if m and m.start() <= pos < max(m.end(), pos + 1):
                        reported.setdefault(m.start(), m)
                pos = hay.find(a, pos + 1)
        for pos in sorted(reported):
            yield data_offset + pos, reported[pos]

    def scan_region(self, buf, start, end, base):
        if self.ignore_case:
            raise NotImplementedError  # needs a lower-cased copy: chunked path
        reported = {}
        for a in self.anchors:
            pos = buf.find(a, start, end)
            while pos != -1:
                if self.regex is None:
                    reported.setdefault(pos, a)
                else:
                    lo = max(start, pos - self.before)
                    m = self.regex.search(buf, lo, min(end, pos + len(a) + self.after))
                    if m and m.start() <= pos < max(m.end(), pos + 1):
                        reported.setdefault(m.start(), m)
                pos = buf.find(a, pos + 1, end)
        for pos in sorted(reported):
            yield base + pos - start, reported[pos]


def scan(layer: DataLayer, scanner: Scanner, chunk_size: int = CHUNK_SIZE,
         start: Optional[int] = None, end: Optional[int] = None,
         progress: Optional[Callable[[int, int], None]] = None) -> Iterator[Tuple[int, object]]:
    """Run ``scanner`` across ``layer`` and yield de-duplicated hits. File-backed layers are searched in place
    (no copies) when the scanner supports it; everything else is read in overlapping chunks."""
    whole = start is None and end is None and progress is None
    if whole:
        from keto.framework import parallel
        specs = parallel.file_specs(layer)
        gen = parallel.parallel_scan(scanner, specs, sum(s[3] for s in specs), parallel.PART_SIZE) if specs else None
        if gen is not None:
            for hit_off, value in gen:
                if scanner.alignment > 1 and hit_off % scanner.alignment:
                    continue
                yield hit_off, value
            return
    regions = layer.regions() if (whole and scanner.scan_region
                                  and not getattr(scanner, "ignore_case", False)) else None
    if regions is not None:
        for loff, buf, bstart, blen in regions:
            for hit_off, value in scanner.scan_region(buf, bstart, bstart + blen, loff):
                if scanner.alignment > 1 and hit_off % scanner.alignment:
                    continue
                yield hit_off, value
        return
    total = layer.size or 1
    done = 0
    tail, tail_end = b"", None  # look-behind: the end of the previous chunk when this one continues it
    for off, data, payload in layer.iter_chunks(chunk_size, scanner.overlap, start, end):
        limit = off + payload
        lb = tail if (tail_end == off and scanner.overlap) else b""
        buf = (bytes(lb) + bytes(data)) if lb else data
        for hit_off, value in scanner(buf, off - len(lb)):
            if hit_off < off or hit_off >= limit:  # starts in the look-behind (reported already) or look-ahead
                continue
            if scanner.alignment > 1 and hit_off % scanner.alignment:
                continue
            yield hit_off, value
        if scanner.overlap:
            tail = bytes(data[max(0, payload - scanner.overlap):payload])
            tail_end = limit
        done += payload
        if progress:
            progress(done, total)


def scan_aligned_u32(layer: DataLayer, field_offset: int, stride: int, predicate: Callable[[int], bool],
                     chunk_size: int = CHUNK_SIZE, prefilter: Optional[Tuple[int, Iterable[int]]] = None
                     ) -> Iterator[Tuple[int, int]]:
    """Check one little-endian u32 at ``base + field_offset`` for every
    ``stride``-aligned base address; yield ``(base, value)`` where ``predicate``
    holds. Reads zero-copy views of file-backed images and strides with
    ``memoryview.cast``. ``prefilter=(byte_offset, values)`` names one byte (relative
    to the base) that must hold one of ``values``: candidates are then located with
    ``bytes.find`` (C speed) and only those reach ``predicate``."""
    assert field_offset % 4 == 0 and stride % 4 == 0
    chunk_size = max(stride, chunk_size - chunk_size % stride)
    pre_off, pre_vals = (prefilter[0], sorted(set(prefilter[1]))) if prefilter else (None, None)
    for off, data in layer.iter_views(chunk_size):
        skew = (-off) % stride
        n = len(data)
        usable = (n - skew) - (n - skew) % stride
        if usable <= 0:
            continue
        mv = memoryview(data)[skew:skew + usable]
        try:
            words = mv.cast("I")[field_offset // 4::stride // 4]
            if pre_vals is None:
                for idx, value in enumerate(words):
                    if predicate(value):
                        yield off + skew + idx * stride, value
                continue
            column = mv[pre_off::stride].tobytes()  # one byte per candidate base
            idxs = set()
            for v in pre_vals:
                i = column.find(v)
                while i != -1:
                    idxs.add(i)
                    i = column.find(v, i + 1)
            for idx in sorted(idxs):
                value = words[idx]
                if predicate(value):
                    yield off + skew + idx * stride, value
        finally:
            mv.release()


def byte_prefilter(field_offset: int, mask: int, values) -> Optional[Tuple[int, set]]:
    """Prefilter for ``scan_aligned_u32`` when ``(word & mask)`` must be in ``values`` and ``mask`` covers a whole
    byte: that byte's offset and its acceptable values. None when no byte of the mask is fully covered."""
    vals = values if isinstance(values, (set, frozenset, list, tuple)) else [values]
    for b in range(4):
        if (mask >> (8 * b)) & 0xFF == 0xFF:
            return field_offset + b, {(v >> (8 * b)) & 0xFF for v in vals}
    return None


def first_hits(hits: Iterable, limit: int):
    for i, h in enumerate(hits):
        if i >= limit:
            break
        yield h
