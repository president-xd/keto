"""``keto acquire --method kcore``: physical RAM of a running Linux kernel (WSL2 included) through
``/proc/kcore``, the same source AVML uses, plus what is needed to analyse it offline: the kernel's BTF,
the symbols the host-memory plugins use, the banner and the address-translation parameters.

Pages that read as all zero are not stored (``zero_pages_omitted``); the analysis layer reads them back as
zeros. Runs of data separated by fewer than ``GAP_PAGES`` zero pages are kept as one segment, and no segment is
longer than ``SEGMENT_MAX`` (a longer run continues in the next segment), so memory use stays bounded.

The output is written through the page cache, i.e. into the RAM being imaged: every ``DROP_EVERY`` bytes the
written part of the file is synced and dropped from the page cache. Dropped pages keep their content until they
are reused, so RAM pages identical to a page of the output file (the file's data sits at a non-page-aligned file
offset, so such a page is the output's own page cache imaged back) are not stored either (``own_pages_omitted``).
``--phys-range`` and ``--max-bytes`` limit the acquisition; the ranges actually covered by a limited or
interrupted acquisition are recorded as ``acquired_ranges`` and the analysis reads nothing outside them as zeros.
"""

from __future__ import annotations

import hashlib
import os
import platform
import time
from typing import Optional

from keto.formats.container import ContainerWriter
from keto.framework.exceptions import RequirementError
from keto.framework.util import parse_size
from keto.hostmem import btf as btf_mod
from keto.hostmem.linux import WANTED_SYMBOLS, KcoreReader, KernelMemory, parse_kallsyms

PAGE = 4096
GAP_PAGES = 8
CHUNK = 16 << 20
SEGMENT_MAX = 16 << 20
DROP_EVERY = 64 << 20
OWN_PAGES_MAX = 1 << 22  # output-file pages remembered (64-bit hashes; 16 GiB of output)
ZERO = bytes(PAGE)
KCORE, KALLSYMS, BTF, VERSION = "/proc/kcore", "/proc/kallsyms", "/sys/kernel/btf/vmlinux", "/proc/version"


class _OwnPages:
    """Hashes of the 4 KiB pages of the output file, fed with everything written to it in order. Uniform pages
    are not recorded (they match at any alignment), nor are file pages that coincide with a stored RAM page (data
    at a page-aligned file offset): a RAM page identical to one of those could be a genuine duplicate."""

    def __init__(self):
        self.hashes = set()
        self.tail = b""  # the incomplete last page of the file
        self.omitted = 0

    def feed(self, data: bytes, ram: bool = False):
        i = 0
        if self.tail:
            i = PAGE - len(self.tail)
            if len(data) < i:
                self.tail += data
                return
            self._add(self.tail + data[:i])
        elif ram:  # page-aligned RAM pages: skip them
            i = len(data) // PAGE * PAGE
        while i + PAGE <= len(data):
            self._add(data[i:i + PAGE])
            i += PAGE
        self.tail = data[i:]

    def _add(self, page: bytes):
        if page.count(page[:1]) != PAGE and len(self.hashes) < OWN_PAGES_MAX:
            self.hashes.add(hash(page))

    def omit(self, page: bytes) -> bool:
        """True (and counted) when ``page`` is identical to a recorded page of the output file."""
        if hash(page) in self.hashes:
            self.omitted += 1
            return True
        return False


def _runs(kc: KcoreReader, vaddr: int, size: int, max_len: int = SEGMENT_MAX, own: Optional[_OwnPages] = None):
    """Yield ``(offset, bytes)`` runs of non-zero pages inside one RAM segment, each at most ``max_len`` bytes
    (plus up to ``GAP_PAGES`` zero pages). Pages of the output file (``own``) count as zero pages."""
    run_start, run, gap = None, bytearray(), 0
    pos = 0
    while pos < size:
        n = min(CHUNK, size - pos)
        data = kc.read(vaddr + pos, n)
        for i in range(0, n, PAGE):
            page = data[i:i + PAGE]
            if page == ZERO[:len(page)] or (own is not None and own.omit(page)):
                if run_start is not None:
                    gap += 1
                    if gap > GAP_PAGES:
                        yield run_start, bytes(run)
                        run_start, run, gap = None, bytearray(), 0
                continue
            if run_start is None:
                run_start = pos + i
            elif gap:
                run += bytes(gap * PAGE)
                gap = 0
            run += page
            if len(run) >= max_len:
                yield run_start, bytes(run)
                run_start, run = None, bytearray()
        pos += n
    if run_start is not None:
        yield run_start, bytes(run)


def parse_ranges(specs) -> list:
    """``["START-END", ...]`` (end exclusive; hex, decimal or sizes like 4G) -> sorted, merged ``[(start, end)]``."""
    out = []
    for spec in specs:
        try:
            start, end = (parse_size(x) for x in spec.split("-", 1))
        except ValueError:
            raise RequirementError("--phys-range %r: expected START-END, e.g. 0x100000000-0x140000000 or 0-4G" % spec)
        if end <= start:
            raise RequirementError("--phys-range %r: END must be above START" % spec)
        out.append((start & ~(PAGE - 1), -(-end // PAGE) * PAGE))  # whole pages
    merged = []
    for start, end in sorted(out):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _clip(ranges, wanted):
    """RAM ``[(paddr, size, vaddr)]`` restricted to the ``wanted`` physical ranges (all of it when none)."""
    if not wanted:
        return list(ranges)
    out = []
    for paddr, size, vaddr in ranges:
        for start, end in wanted:
            s, e = max(paddr, start), min(paddr + size, end)
            if s < e:
                out.append((s, e - s, vaddr + (s - paddr)))
    return out


def _drop_written(fh, start: int) -> int:
    """Sync the file written since ``start`` and drop it from the page cache; returns the new start."""
    fh.flush()
    end = fh.tell()
    os.fdatasync(fh.fileno())
    os.posix_fadvise(fh.fileno(), start, end - start, os.POSIX_FADV_DONTNEED)
    return end


def acquire_kcore(args, out, base_metadata) -> int:
    if not os.path.exists(KCORE):
        raise RequirementError("kcore method needs Linux with /proc/kcore (CONFIG_PROC_KCORE)")
    wanted = parse_ranges(getattr(args, "phys_range", None) or [])
    max_bytes = getattr(args, "max_bytes", None)
    try:
        kc = KcoreReader(KCORE)
    except PermissionError:
        raise RequirementError("reading /proc/kcore needs root (e.g. 'wsl -u root' or sudo)")
    with open(KALLSYMS, "r") as fh:
        all_syms = parse_kallsyms(fh.read())
    if "init_task" not in all_syms:
        raise RequirementError("/proc/kallsyms shows no addresses (kptr_restrict): run as root")
    syms = {k: all_syms[k] for k in WANTED_SYMBOLS if k in all_syms}
    btf_blob = b""
    if os.path.exists(BTF):
        with open(BTF, "rb") as fh:
            btf_blob = fh.read()
    if not btf_blob:
        raise RequirementError("kernel has no BTF (/sys/kernel/btf/vmlinux): struct layouts cannot be recorded")
    km = KernelMemory(btf_mod.Btf(btf_blob), syms, kcore=kc)  # phys_base from the kernel-text segment
    ranges = kc.ram_ranges(km.page_offset_base)
    if not ranges:
        raise RequirementError("no direct-map RAM segments in /proc/kcore")
    plan = _clip(ranges, wanted)
    if not plan:
        raise RequirementError("--phys-range covers no RAM (RAM: %s)" % ", ".join(
            "0x%x-0x%x" % (p, p + s) for p, s, _v in ranges))
    with open(VERSION, "r") as fh:
        banner = fh.read().strip()
    meta = base_metadata
    meta["kernel"] = {"os": "linux", "arch": "x86_64", "banner": banner, "release": platform.release(),
                      "symbols": {k: "0x%x" % v for k, v in syms.items()},
                      "phys_base": "0x%x" % km.phys_base if km.phys_base is not None else None,
                      "page_offset_base": "0x%x" % km.page_offset_base, "l5": km.l5,
                      "zero_pages_omitted": True, "btf_sha256": hashlib.sha256(btf_blob).hexdigest(),
                      "ram_ranges": [{"start": "0x%x" % p, "size": s} for p, s, _v in ranges]}
    notes = ("physical RAM through /proc/kcore (direct-map segments); all-zero pages omitted; kernel BTF and %d "
             "symbols stored for offline analysis" % len(syms))
    writer = ContainerWriter(args.out, meta, exclusive=not getattr(args, "force", False))
    t0 = time.time()
    stored = 0
    acquired = []  # [(paddr, bytes of RAM covered from there)]
    stop = None  # why the acquisition ended before the end of the plan
    own = _OwnPages()
    try:
        own.feed(bytes(writer.fh.tell()))  # header placeholder
        writer.add_segment("kbtf", 0, btf_blob)
        own.feed(btf_blob)
        dropped = 0
        for paddr, size, vaddr in plan:
            acquired.append((paddr, 0))
            for off, data in _runs(kc, vaddr, size, SEGMENT_MAX, own):
                if max_bytes is not None and stored + len(data) > max_bytes:
                    data = data[:(max_bytes - stored) // PAGE * PAGE]
                    stop = "--max-bytes %d reached" % max_bytes
                if data:
                    writer.add_segment("sysmem", paddr + off, data)
                    own.feed(data, ram=True)
                    stored += len(data)
                acquired[-1] = (paddr, off + len(data))
                if writer.fh.tell() - dropped >= DROP_EVERY:
                    dropped = _drop_written(writer.fh, dropped)
                if stop:
                    break
            if stop:
                break
            acquired[-1] = (paddr, size)
        _drop_written(writer.fh, dropped)
    except BaseException as exc:
        stop = "interrupted: %s" % (type(exc).__name__)
        raise
    finally:
        acquired = [(p, s) for p, s in acquired if s]
        meta["kernel"]["own_pages_omitted"] = own.omitted
        if own.omitted:
            notes += ("; %d page(s) identical to pages of this output file (its own page cache, live or freed) "
                      "not stored" % own.omitted)
        if wanted or stop:  # the analysis must not read the RAM left out as zero pages
            meta["kernel"]["acquired_ranges"] = [{"start": "0x%x" % p, "size": s} for p, s in acquired]
            notes += "; acquired only %s" % (", ".join("0x%x-0x%x" % (p, p + s) for p, s in acquired) or "nothing")
            if stop:
                notes += " (%s)" % stop
        meta["acquisition"]["notes"] = notes
        writer.metadata = meta
        writer.close()
        kc.close()
    out.write("kernel %s: %d MiB RAM read in %d range(s), %d MiB non-zero stored in %d segment(s) -> %s in %.1fs%s\n"
              % (platform.release(), sum(s for _p, s in acquired) >> 20, len(acquired), stored >> 20,
                 len(writer.segments) - 1, args.out, time.time() - t0, " (%s)" % stop if stop else ""))
    return 0
