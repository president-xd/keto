"""Windows 8+ hibernation files (hiberfil.sys, x64) as a physical-address layer.

Format (Sylve, Marziale & Richard, "Modern Windows hibernation file analysis", Digital Investigation 20, 2017;
offsets of ``PO_MEMORY_IMAGE``/``_PO_HIBER_PERF`` per build from the Vergilius Project's PDB-derived listings):

* Page 0: ``PO_MEMORY_IMAGE``. Signature "HIBR" (hibernated), "HORM" (hibernate once / resume many), "RSTR" (being
  resumed), "WAKE" (resumed: Windows zeroes everything after the first 4 KiB, so no memory is left). LengthSelf is
  sizeof(PO_MEMORY_IMAGE) and identifies the layout. Page 1 (0x1000): ``_KPROCESSOR_STATE`` (CR3 at 0x1010).
* Restoration sets: the boot set starts at page FirstBootRestorePage and holds NumPagesForLoader pages (also
  PerfInfo.BootPagesProcessed); the kernel set starts at FirstKernelRestorePage (0 = none) and holds
  PerfInfo.KernelPagesProcessed pages. FirstSecureRestorePage (Windows 10+) is the Secure Kernel's set (encrypted;
  not decoded).
* A restoration set is a chain of compression sets: u32 header (bits 0-7 descriptor count 1..16; then the
  compressed size and the codec, see ``SET_FORMATS``), that many u64 page descriptors (bits 0-3 page count - 1,
  bits 4-63 first PFN), then the data: stored when its size equals pages x 4096, otherwise Xpress (plain LZ77) or
  Xpress Huffman. A set covers at most 16 pages; the next set follows immediately.

Per-build header offsets (absolute; PerfInfo at 0x70 on 8/8.1 and 0x88 on 10/11):

    build                     LengthSelf     FirstBoot FirstKernel BootPagesProcessed KernelPagesProcessed
    8, 8.1                    0x360          0x60      0x68        0x1C0              0x1C8
    10 1507/1511              0x3B0          0x68      0x70        0x210              0x218
    10 1607                   0x3C8          0x68      0x70        0x218              0x220
    10 1703 .. 11 23H2        0x3D8/0x3E0/0x448  0x68  0x70        0x228              0x230
    11 24H2/25H2              0x4D8          0x68      0x70        0x230              0x238
    11 26H2 (later 26100+)    0x4F0          0x68      0x70        0x248              0x250

The layout is chosen by LengthSelf and must be confirmed by walking the compression-set chains (they must add up to
the page counts exactly); an unknown LengthSelf tries every layout and reports which one the chains confirmed.
"""

from __future__ import annotations

import array
import bisect
import collections
import datetime
import mmap
import os
import struct
from typing import Dict, List, Tuple

from keto.formats import xpress
from keto.framework.exceptions import FormatError, InvalidAddressException, UnsupportedError
from keto.framework.layers import DataLayer

PAGE = 0x1000
STORED, XPRESS, HUFFMAN = 0, 1, 2
CODEC_NAMES = {STORED: "stored", XPRESS: "xpress", HUFFMAN: "xpress_huffman"}
#: compression-set header bits: (size mask after >> 8, Huffman bit). "classic": 22-bit size, bit 31 = Huffman (Sylve
#: et al.); "24h2": 21-bit size, bit 30 = Huffman (Volatility 3 PR #1036's Windows 11 24H2 analysis)
SET_FORMATS = {"classic": (0x3FFFFF, 31), "24h2": (0x1FFFFF, 30)}
#: (name, LengthSelf values, FirstBootRestorePage, FirstKernelRestorePage, BootPagesProcessed, KernelPagesProcessed,
#: HighestPhysicalPage, set format, FirstSecureRestorePage)
LAYOUTS = (
    ("windows-8/8.1", (0x360,), 0x60, 0x68, 0x1C0, 0x1C8, 0x330, "classic", None),
    ("windows-10-1507/1511", (0x3B0,), 0x68, 0x70, 0x210, 0x218, 0x380, "classic", 0x60),
    ("windows-10-1607", (0x3C8,), 0x68, 0x70, 0x218, 0x220, 0x388, "classic", 0x60),
    ("windows-10-1703..windows-11-23h2", (0x3D8, 0x3E0, 0x448), 0x68, 0x70, 0x228, 0x230, None, "classic", 0x60),
    ("windows-11-24h2/25h2", (0x4D8,), 0x68, 0x70, 0x230, 0x238, 0x498, "24h2", 0x60),
    ("windows-11-26h2", (0x4F0,), 0x68, 0x70, 0x248, 0x250, 0x4B0, "24h2", 0x60),
)
_HIGHEST_1703 = {0x3D8: 0x398, 0x3E0: 0x398, 0x448: 0x400}
SIGNATURES = {b"HIBR": "hibernated", b"HORM": "hibernate-once-resume-many", b"RSTR": "resuming",
              b"WAKE": "resumed"}
LEGACY_SIGNATURES = (b"hibr", b"wake", b"rstr")
LEGACY_XPRESS = b"\x81\x81xpress"
PROCESSOR_STATE = 0x1000
CACHE_SETS = 1024
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def looks_like(head: bytes) -> bool:
    """A hibernation signature plus a 4 KiB page size where x64 (0x18) or x86 (0x14) headers keep it."""
    if len(head) < 0x20 or (head[:4] not in SIGNATURES and head[:4] not in LEGACY_SIGNATURES):
        return False
    ps64, ps32 = struct.unpack_from("<I", head, 0x18)[0], struct.unpack_from("<I", head, 0x14)[0]
    return PAGE in (ps64, ps32)


class _Bad(Exception):
    pass


class _Chains:
    """Compression sets and their page descriptors, appended while walking restoration sets."""

    def __init__(self):
        self.set_off = array.array("Q")
        self.set_size = array.array("I")
        self.set_codec = array.array("B")
        self.set_pages = array.array("B")
        self.run_pfn = array.array("Q")
        self.run_cnt = array.array("B")
        self.run_set = array.array("I")
        self.run_idx = array.array("B")
        self.flag_bits = collections.Counter()

    def walk(self, mm, size: int, first_page: int, total: int, set_format: str, what: str) -> None:
        mask, hbit = SET_FORMATS[set_format]
        off = first_page * PAGE
        got = 0
        unpack = struct.unpack_from
        set_off, set_size, set_codec, set_pages = self.set_off, self.set_size, self.set_codec, self.set_pages
        run_pfn, run_cnt, run_set, run_idx = self.run_pfn, self.run_cnt, self.run_set, self.run_idx
        while got < total:
            if off + 4 > size:
                raise _Bad("%s: compression set %d starts at 0x%x, beyond the end of the file (%d bytes), after %d "
                           "of %d pages" % (what, len(set_off), off, size, got, total))
            h = unpack("<I", mm, off)[0]
            nd = h & 0xFF
            if not 1 <= nd <= 16:
                raise _Bad("%s: compression set header 0x%08x at file offset 0x%x has %d page descriptors (valid: "
                           "1..16), after %d of %d pages" % (what, h, off, nd, got, total))
            csize = (h >> 8) & mask
            data = off + 4 + 8 * nd
            if data > size:
                raise _Bad("%s: page descriptors of the set at 0x%x run past the end of the file" % (what, off))
            si = len(set_off)
            npages = 0
            for d in unpack("<%dQ" % nd, mm, off + 4):
                c = (d & 0xF) + 1
                run_pfn.append(d >> 4)
                run_cnt.append(c)
                run_set.append(si)
                run_idx.append(npages)
                npages += c
            if npages > 16:
                raise _Bad("%s: the set at 0x%x describes %d pages (a set holds at most 16)" % (what, off, npages))
            if csize == 0 or csize > npages * PAGE or data + csize > size:
                raise _Bad("%s: the set at 0x%x (header 0x%08x) has %d data bytes for %d pages ending at 0x%x (file "
                           "%d bytes)" % (what, off, h, csize, npages, data + csize, size))
            set_off.append(data)
            set_size.append(csize)
            set_codec.append(STORED if csize == npages * PAGE else (HUFFMAN if (h >> hbit) & 1 else XPRESS))
            set_pages.append(npages)
            other = h & ~(0xFF | (mask << 8) | (1 << hbit)) & 0xFFFFFFFF
            if other:
                self.flag_bits[other] += 1
            got += npages
            off = data + csize
        if got != total:
            raise _Bad("%s: the compression sets hold %d pages, the header says %d" % (what, got, total))


class HiberLayer(DataLayer):
    """Pages of a hibernation file, decompressed on demand (one LRU cache entry per compression set)."""

    KIND = "hiber"

    def __init__(self, name: str, path: str, fh, mm, chains: _Chains):
        super().__init__(name)
        self.path = path
        self._fh, self._mm = fh, mm
        self._set_off, self._set_size = chains.set_off, chains.set_size
        self._set_codec, self._set_pages = chains.set_codec, chains.set_pages
        self.duplicate_pages = self._index(chains)
        self._cache: "collections.OrderedDict[int, bytes]" = collections.OrderedDict()
        self.decompressions = 0
        self.problems: List[str] = []

    def _index(self, c: _Chains) -> int:
        n = len(c.run_pfn)
        pfn = c.run_pfn
        ordered = all(pfn[i] + c.run_cnt[i] <= pfn[i + 1] for i in range(n - 1))
        dup = 0
        if ordered:
            self._pfn, self._cnt, self._set, self._idx = pfn, c.run_cnt, c.run_set, c.run_idx
        else:
            order = sorted(range(n), key=pfn.__getitem__)
            overlap = any(pfn[order[k]] + c.run_cnt[order[k]] > pfn[order[k + 1]] for k in range(n - 1))
            if not overlap:
                self._pfn = array.array("Q", (pfn[i] for i in order))
                self._cnt = array.array("B", (c.run_cnt[i] for i in order))
                self._set = array.array("I", (c.run_set[i] for i in order))
                self._idx = array.array("B", (c.run_idx[i] for i in order))
            else:  # a PFN in more than one set: the later set (kernel restores after the loader) wins
                pages: Dict[int, tuple] = {}
                for i in range(n):
                    for k in range(c.run_cnt[i]):
                        p = pfn[i] + k
                        if p in pages:
                            dup += 1
                        pages[p] = (c.run_set[i], c.run_idx[i] + k)
                self._pfn, self._cnt = array.array("Q"), array.array("B")
                self._set, self._idx = array.array("I"), array.array("B")
                for p in sorted(pages):
                    s, k = pages[p]
                    if (self._pfn and self._pfn[-1] + self._cnt[-1] == p and self._set[-1] == s
                            and self._idx[-1] + self._cnt[-1] == k and self._cnt[-1] < 255):
                        self._cnt[-1] += 1
                    else:
                        self._pfn.append(p)
                        self._cnt.append(1)
                        self._set.append(s)
                        self._idx.append(k)
        ranges: List[Tuple[int, int]] = []
        cur_start = cur_end = -1
        for p, c in zip(self._pfn, self._cnt):
            if p * PAGE != cur_end:
                if cur_end >= 0:
                    ranges.append((cur_start, cur_end - cur_start))
                cur_start = p * PAGE
            cur_end = (p + c) * PAGE
        if cur_end >= 0:
            ranges.append((cur_start, cur_end - cur_start))
        self._ranges = ranges
        self._range_starts = [s for s, _ in ranges]
        return dup

    def ranges(self):
        return self._ranges

    def _starts(self):
        return self._ranges, self._range_starts

    @property
    def page_count(self) -> int:
        return sum(self._cnt)

    def set_data(self, si: int) -> bytes:
        """The decompressed pages of compression set ``si``."""
        off, size, codec = self._set_off[si], self._set_size[si], self._set_codec[si]
        if codec == STORED:
            return self._mm[off:off + size]
        hit = self._cache.get(si)
        if hit is not None:
            self._cache.move_to_end(si)
            return hit
        raw = self._mm[off:off + size]
        out_size = self._set_pages[si] * PAGE
        self.decompressions += 1
        try:
            data = _decode(codec, raw, out_size)
        except xpress.XpressError as first:
            other = XPRESS if codec == HUFFMAN else HUFFMAN
            try:
                data = _decode(other, raw, out_size)
            except xpress.XpressError:
                raise InvalidAddressException(self.name, 0, "hiberfil %s: the %s compression set at file offset 0x%x "
                                              "(%d bytes, %d pages) does not decompress: %s"
                                              % (self.path, CODEC_NAMES[codec], off - 4, size,
                                                 self._set_pages[si], first))
            self.problems.append("compression set at file offset 0x%x is flagged %s but decodes as %s"
                                 % (off, CODEC_NAMES[codec], CODEC_NAMES[other]))
        self._cache[si] = data
        if len(self._cache) > CACHE_SETS:
            self._cache.popitem(last=False)
        return data

    def _read_run(self, offset, length):
        out = []
        pos, end = offset, offset + length
        pfns = self._pfn
        while pos < end:
            pfn = pos >> 12
            i = bisect.bisect_right(pfns, pfn) - 1
            k = pfn - pfns[i] if i >= 0 else -1
            if k < 0 or k >= self._cnt[i]:
                raise InvalidAddressException(self.name, pos)
            try:
                data = self.set_data(self._set[i])
            except InvalidAddressException as exc:
                raise InvalidAddressException(self.name, pos, "%s (reading 0x%x)" % (exc, pos))
            start = (self._idx[i] + k) * PAGE + (pos & 0xFFF)
            take = min(end - pos, (self._cnt[i] - k) * PAGE - (pos & 0xFFF))
            out.append(data[start:start + take])
            pos += take
        return b"".join(out)

    def close(self):
        if self._mm is not None and not self._mm.closed:
            self._mm.close()
        self._fh.close()


def _decode(codec: int, raw: bytes, out_size: int) -> bytes:
    if codec == HUFFMAN:
        return xpress.huffman_decompress(raw, out_size)
    return xpress.lz77_decompress(raw, out_size)


def _u32(mm, off):
    return struct.unpack_from("<I", mm, off)[0]


def _u64(mm, off):
    return struct.unpack_from("<Q", mm, off)[0]


def _try_layout(mm, size: int, layout):
    name, _ls, fbrp, fkrp, bpp, kpp, _hpp, set_format, _fsrp = layout
    npfl = _u64(mm, 0x58)
    first_boot, first_kernel = _u64(mm, fbrp), _u64(mm, fkrp)
    kernel_pages = _u64(mm, kpp)
    chains = _Chains()
    if npfl and first_boot:
        chains.walk(mm, size, first_boot, npfl, set_format, "boot restoration set (%s layout)" % name)
    if first_kernel:
        if not kernel_pages:
            raise _Bad("kernel restoration set (%s layout) at page %d but KernelPagesProcessed (0x%x) is 0"
                       % (name, first_kernel, kpp))
        chains.walk(mm, size, first_kernel, kernel_pages, set_format, "kernel restoration set (%s layout)" % name)
    if not len(chains.set_off):
        raise _Bad("%s layout: no restoration set (NumPagesForLoader %d, FirstBootRestorePage %d, "
                   "FirstKernelRestorePage %d)" % (name, npfl, first_boot, first_kernel))
    return chains, {"num_pages_for_loader": npfl, "first_boot_restore_page": first_boot,
                    "first_kernel_restore_page": first_kernel, "kernel_pages_processed": kernel_pages,
                    "boot_pages_processed": _u64(mm, bpp)}


def open_hiber(name: str, path: str):
    size = os.path.getsize(path)
    if size < 2 * PAGE:
        raise FormatError("%s is too small for a hibernation file (%d bytes)" % (path, size))
    fh = open(path, "rb")
    try:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    except Exception:
        fh.close()
        raise
    try:
        return _open(name, path, fh, mm, size)
    except BaseException:
        mm.close()
        fh.close()
        raise


def _open(name: str, path: str, fh, mm, size: int):
    sig = mm[:4]
    if sig in LEGACY_SIGNATURES:
        raise UnsupportedError("%s: signature %r is the Windows XP-7 hibernation format (table pages + "
                               "'\\x81\\x81xpress' blocks), which is not supported; Windows 8+ files are" % (path, sig))
    if sig not in SIGNATURES:
        raise FormatError("%s is not a hibernation file (signature %r)" % (path, sig))
    page_size = _u32(mm, 0x18)
    if page_size != PAGE:
        if _u32(mm, 0x14) == PAGE:
            raise UnsupportedError("%s is a 32-bit (x86) hibernation file (PageSize at 0x14): only x64 files are "
                                   "supported" % path)
        raise FormatError("%s: PageSize is %d, expected 4096" % (path, page_size))
    length_self = _u32(mm, 0x0C)
    matching = [l for l in LAYOUTS if length_self in l[1]]
    # the LengthSelf match first, then the others: a servicing update can move PerfInfo fields without changing
    # LengthSelf (Volatility 3 PR #1036 saw KernelPagesProcessed at 0x238 and 0x250 in Windows 11 build 26100)
    candidates = matching + [l for l in LAYOUTS if l not in matching]
    failures = []
    chosen = None
    for layout in candidates:
        try:
            chains, counts = _try_layout(mm, size, layout)
        except _Bad as exc:
            failures.append(str(exc))
            continue
        chosen = layout
        break
    if chosen is None:
        detail = "; ".join(failures)
        if sig == b"WAKE":
            raise UnsupportedError("%s: signature 'WAKE' - Windows resumed from this file and zeroes everything "
                                   "after its first 4 KiB, so it holds no memory pages (%s)" % (path, detail))
        if mm.find(LEGACY_XPRESS, 0, min(size, 1 << 20)) >= 0:
            raise UnsupportedError("%s: '\\x81\\x81xpress' blocks found: this is the Windows XP-7 hibernation format, "
                                   "which is not supported" % path)
        raise FormatError("%s: LengthSelf 0x%x %s, and no layout's restoration sets check out: %s"
                          % (path, length_self, "matches a known build" if matching else "is not a known build",
                             detail))
    lname, _ls, fbrp, fkrp, bpp, kpp, hpp, set_format, fsrp = chosen
    if hpp is None:
        hpp = _HIGHEST_1703.get(length_self)
    warnings = []
    inferred = chosen not in matching
    if not matching:
        warnings.append("LengthSelf 0x%x is not a known Windows build; the %s layout was chosen because its "
                        "restoration sets add up to the header's page counts" % (length_self, lname))
    elif inferred:
        warnings.append("LengthSelf 0x%x names the %s layout, but its restoration sets do not check out (%s); the %s "
                        "layout's do" % (length_self, matching[0][0], failures[0], lname))
    if sig == b"RSTR":
        warnings.append("signature 'RSTR': the file was captured while Windows was resuming from it; its pages "
                        "are those written at hibernation")
    elif sig == b"WAKE":
        warnings.append("signature 'WAKE' (resumed) but restoration sets are still present")
    if counts["num_pages_for_loader"] != counts["boot_pages_processed"]:
        warnings.append("NumPagesForLoader (%d) differs from PerfInfo.BootPagesProcessed (%d at 0x%x)"
                        % (counts["num_pages_for_loader"], counts["boot_pages_processed"], bpp))
    first_secure = _u64(mm, fsrp) if fsrp is not None else 0
    if first_secure:
        warnings.append("a secure restoration set (Secure Kernel/VSM, encrypted) starts at page %d and is not "
                        "decoded" % first_secure)
    if chains.flag_bits:
        warnings.append("compression set headers carry bits outside the documented fields: %s"
                        % ", ".join("0x%08x x%d" % kv for kv in sorted(chains.flag_bits.items())))
    layer = HiberLayer(name, path, fh, mm, chains)
    if layer.duplicate_pages:
        warnings.append("%d page(s) appear in more than one compression set; the later set's copy is used"
                        % layer.duplicate_pages)
    highest = _u64(mm, hpp) if hpp is not None else None
    if highest and layer.ranges() and layer.maximum_address // PAGE > highest:
        warnings.append("pages above HighestPhysicalPage (0x%x) are present" % highest)
    cr = struct.unpack_from("<4Q", mm, PROCESSOR_STATE)
    st = _u64(mm, 0x20)
    try:
        system_time = (_FILETIME_EPOCH + datetime.timedelta(microseconds=st // 10)).isoformat().replace("+00:00", "Z") \
            if st else None
    except OverflowError:
        system_time = None
    codecs = collections.Counter(CODEC_NAMES[c] for c in chains.set_codec)
    meta = {"format": "hiber", "signature": sig.decode("latin-1"), "state": SIGNATURES[sig],
            "usable": True, "layout": lname, "layout_inferred": inferred, "set_format": set_format,
            "length_self": length_self, "page_size": page_size, "system_time": system_time,
            "first_secure_restore_page": first_secure, "highest_physical_page": highest,
            "cr0": cr[0], "cr2": cr[1], "cr3": cr[2], "cr4": cr[3],
            "compression_sets": len(chains.set_off), "codecs": dict(codecs), "pages": layer.page_count,
            "duplicate_pages": layer.duplicate_pages, "physical_runs": list(layer.ranges()),
            "warnings": warnings, "decode_problems": layer.problems}
    meta.update(counts)
    return layer, meta
