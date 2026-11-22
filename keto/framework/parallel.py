"""Multi-core scanning of large file-backed images.

``scan()`` hands a scanner here when the layer's regions are file mappings and the image is large: the regions are
split into parts (each extended by the scanner's overlap), every worker process maps the file itself (nothing is
copied between processes) and runs the scanner's in-place ``scan_region`` on its part, and the hits come back in
order. Regex matches are returned as :class:`PMatch`, which offers the match methods plugins use.

Workers: ``KETO_WORKERS`` (or ``--workers``); 0 or 1 disables parallel scanning.
"""

from __future__ import annotations

import atexit
import mmap
import os
import pickle
from typing import Dict, List, Optional, Sequence, Tuple

PARALLEL_MIN = 512 << 20   # images smaller than this are scanned in-process
PART_SIZE = 256 << 20
_POOL = None
_POOL_SIZE = 0
_IN_WORKER = False


class PMatch:
    """A picklable stand-in for ``re.Match`` (positions are relative to the scanned buffer region)."""

    __slots__ = ("_groups", "_spans", "lastindex")

    def __init__(self, m):
        n = (m.re.groups if hasattr(m, "re") else 0) + 1
        self._groups = tuple(m.group(i) for i in range(n))
        self._spans = tuple(m.span(i) for i in range(n))
        self.lastindex = m.lastindex

    def group(self, *idx):
        if not idx:
            return self._groups[0]
        if len(idx) == 1:
            return self._groups[idx[0]]
        return tuple(self._groups[i] for i in idx)

    def groups(self):
        return self._groups[1:]

    def start(self, g=0):
        return self._spans[g][0]

    def end(self, g=0):
        return self._spans[g][1]

    def span(self, g=0):
        return self._spans[g]

    def __getitem__(self, g):
        return self._groups[g]


def workers() -> int:
    env = os.environ.get("KETO_WORKERS")
    if env is not None:
        try:
            return max(0, int(env))
        except ValueError:
            return 0
    return min(os.cpu_count() or 1, 8)


def _shutdown():
    global _POOL
    if _POOL is not None:
        try:
            _POOL.shutdown(wait=False, cancel_futures=True)
        except TypeError:  # Python 3.8: no cancel_futures
            _POOL.shutdown(wait=False)
        _POOL = None


def _pool(n: int):
    global _POOL, _POOL_SIZE
    if _POOL is None or _POOL_SIZE != n:
        from concurrent.futures import ProcessPoolExecutor
        _shutdown()
        _POOL = ProcessPoolExecutor(max_workers=n, initializer=_mark_worker)
        _POOL_SIZE = n
        atexit.register(_shutdown)
    return _POOL


def _mark_worker():
    global _IN_WORKER
    _IN_WORKER = True


def _scan_part(scanner_blob: bytes, path: str, fstart: int, fend: int, keep_from: int, limit: int, loff: int):
    """Worker: scan file bytes [fstart, fend) (``fstart`` includes look-behind before the part, ``fend`` the
    overlap after it; ``loff`` is the layer offset of ``fstart``); keep hits starting in [keep_from, limit). The
    look-behind lets a match that began before the part be recognised as such, instead of its tail being
    reported as a new match at the part boundary."""
    scanner = pickle.loads(scanner_blob)
    out = []
    # mapped per task and unmapped before returning, so no worker keeps the evidence file open (Windows locks it)
    with open(path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            if scanner.scan_region is not None and not getattr(scanner, "ignore_case", False):
                hits = scanner.scan_region(mm, fstart, fend, loff)
            else:  # scanners that need their own copy of the data (e.g. case-folding) get it chunk by chunk
                hits = _chunked(scanner, mm, fstart, fend, loff)
            for hit, value in hits:
                if hit < keep_from or hit >= limit:
                    continue
                if hasattr(value, "re") and hasattr(value, "span"):  # re.Match -> picklable copy
                    value = PMatch(value)
                out.append((hit, value))
            del hits
        finally:
            import gc
            gc.collect()  # drop regex iterators still exporting the mapping's buffer
            mm.close()
    return out


def _chunked(scanner, mm, fstart, fend, loff, chunk=16 << 20):
    """Scan ``mm[fstart:fend]`` in copied chunks, each with ``overlap`` bytes of look-behind and look-ahead;
    hits are kept only when they start inside the chunk's own payload."""
    lb = scanner.overlap
    pos = fstart
    while pos < fend:
        n = min(chunk, fend - pos)
        s = max(fstart, pos - lb)
        data = mm[s:min(fend, pos + n + scanner.overlap)]
        lo, hi = loff + (pos - fstart), loff + (pos - fstart) + n
        for hit, value in scanner(data, loff + (s - fstart)):
            if lo <= hit < hi:
                yield hit, value
        pos += n


def plan(specs: Sequence[Tuple[int, str, int, int]], overlap: int, part_size: int = PART_SIZE
         ) -> List[Tuple[str, int, int, int, int, int]]:
    """Split file-backed regions ``(layer offset, path, file start, length)`` into worker tasks
    ``(path, scan start incl. look-behind, scan end incl. overlap, keep-from layer offset, layer-offset limit,
    layer offset of the scan start)``. Each part reads ``overlap`` bytes before and after itself (within its
    region) but keeps only hits that start inside it, so every hit is reported exactly once."""
    tasks = []
    for loff, path, fstart, length in specs:
        pos = 0
        while pos < length:
            n = min(part_size, length - pos)
            s = max(0, pos - overlap)
            end = min(length, pos + n + overlap)
            tasks.append((path, fstart + s, fstart + end, loff + pos, loff + pos + n, loff + s))
            pos += n
    return tasks


def parallel_scan(scanner, specs, total: int, part_size: int = PART_SIZE, force: bool = False):
    """Yield hits in offset order of parts, or return None when the scan should stay in-process."""
    n = workers()
    if _IN_WORKER or n <= 1 or (total < PARALLEL_MIN and not force) or not specs:
        return None
    try:
        blob = pickle.dumps(scanner)
    except Exception:
        return None
    tasks = plan(specs, scanner.overlap, part_size)
    if len(tasks) < 2 and not force:
        return None
    pool = _pool(n)
    futures = [pool.submit(_scan_part, blob, *t) for t in tasks]

    def gen():
        for f in futures:
            for hit, value in f.result():
                yield hit, value
    return gen()


def file_specs(layer) -> Optional[List[Tuple[int, str, int, int]]]:
    """``[(layer offset, path, file start, length)]`` for a layer whose regions are file mappings."""
    fn = getattr(layer, "region_specs", None)
    return fn() if fn else None
