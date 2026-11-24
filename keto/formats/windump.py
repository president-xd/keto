"""Windows kernel crash dumps and live kernel dumps, 64-bit ("PAGEDU64"), as a physical-address layer.

Layout (offsets from kdmp-parser's ``HEADER64``/``BMP_HEADER64``/``RDMP_HEADER64`` and Volatility 3's
``_DUMP_HEADER64``/``_SUMMARY_DUMP64``; see docs/FORMATS.md for the full table and sources):

    0x0000  DUMP_HEADER64 (0x2000 bytes): "PAGE" "DU64", versions, DirectoryTableBase, PsLoadedModuleList,
            PsActiveProcessHead, machine, CPUs, bugcheck, KdDebuggerDataBlock, PhysicalMemoryBlock @0x88,
            DumpType @0xF98, SystemTime @0xFA8, Comment @0xFB0 ...
    0x2000  DumpType 1 (full):            page data of the PhysicalMemoryBlock runs, back to back
            DumpType 5/6 (bitmap/live):   BMP header "SDMP"|"FDMP" "DUMP", FirstPage @+0x20 (file offset of the
                                          first page), TotalPresentPages @+0x28, Pages @+0x30 (bits), bitmap @+0x38;
                                          bit i (LSB first) set = PFN i present, pages stored in PFN order
            DumpType 8/9/0xA (RDMP):      0x40 "RDMP" "DUMP", MetadataSize @+0x10, FirstPageOffset @+0x18,
                                          PFN ranges (u64 PFN, u64 count) from 0x2030 up to FirstPageOffset

Refused with a precise reason: 32-bit dumps ("PAGEDUMP"), triage/mini dumps (type 4), the legacy summary type 2,
unknown types, and headers whose structure does not add up.
"""

from __future__ import annotations

import array
import datetime
import os
import re
import struct
from typing import Iterator, List, Tuple

from keto.formats.memimage import PAGE, file_runs
from keto.framework.exceptions import FormatError, UnsupportedError

SIG64 = b"PAGEDU64"
SIG32 = b"PAGEDUMP"
HEADER_SIZE = 0x2000
_FIXED = struct.Struct("<4s4sIIQQQQIII4x4Q32sQ")            # 0x000..0x088
_PHYSMEM = struct.Struct("<IIQ")                           # 0x088: NumberOfRuns, pad, NumberOfPages; runs @0x098
_TAIL = struct.Struct("<I4xqq128sqIIIIIBB2xII")            # 0xF98 DumpType .. 0x1058 BootId
MAX_RUNS = (700 - 0x10) // 0x10                            # PhysicalMemoryBlockBuffer is 700 bytes
DUMP_TYPES = {1: "full", 2: "kernel_summary", 4: "triage", 5: "bitmap", 6: "live_kernel_bitmap",
              8: "kernel_memory", 9: "kernel_and_user_memory", 10: "complete_memory"}
BMP_SIGNATURES = {b"SDMP": "bitmap_kernel", b"FDMP": "bitmap_full"}
MACHINES = {0x14C: "x86", 0x1C4: "arm", 0x8664: "x64", 0xAA64: "arm64"}
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def looks_like(head: bytes) -> bool:
    """'PAGE' + 'DU64' (64-bit) or 'DUMP' (32-bit, recognised so it is refused rather than opened raw)."""
    return len(head) >= 8 and head[:4] == b"PAGE" and head[4:8] in (b"DU64", b"DUMP")


def filetime_iso(ft: int):
    if ft <= 0:
        return None
    try:
        t = _FILETIME_EPOCH + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None
    return t.isoformat().replace("+00:00", "Z")


def parse_header(head: bytes) -> dict:
    """The DUMP_HEADER64 facts (no physical-memory layout yet)."""
    if len(head) < 0x1058:
        raise FormatError("crash dump header is truncated: %d of 8192 bytes" % len(head))
    (_sig, _valid, major, minor, dtb, pfndb, modules, procs, machine, ncpu, bugcheck, p0, p1, p2, p3,
     _version_user, kddebugger) = _FIXED.unpack_from(head, 0)
    (dump_type, required, system_time, comment, uptime, minidump_fields, secondary, product, suite, writer,
     _unused1, kd_secondary, attributes, boot_id) = _TAIL.unpack_from(head, 0xF98)
    if comment.startswith(b"PAGEPAGE"):
        comment = b""  # unused header bytes are filled with the "PAGE" pattern
    return {
        "format": "windump", "dump_type_value": dump_type, "dump_type": DUMP_TYPES.get(dump_type, "unknown"),
        "major_version": major, "minor_version": minor, "directory_table_base": dtb, "pfn_database": pfndb,
        "ps_loaded_module_list": modules, "ps_active_process_head": procs, "kd_debugger_data_block": kddebugger,
        "machine_image_type": machine, "machine": MACHINES.get(machine, "0x%x" % machine),
        "number_processors": ncpu, "bugcheck_code": bugcheck, "bugcheck_parameters": [p0, p1, p2, p3],
        "system_time": filetime_iso(system_time), "system_time_raw": system_time, "system_up_time": uptime,
        "required_dump_space": required, "comment": comment.split(b"\x00", 1)[0].decode("latin-1"),
        "mini_dump_fields": minidump_fields, "secondary_data_state": secondary, "product_type": product,
        "suite_mask": suite, "writer_status": writer, "kd_secondary_version": kd_secondary,
        "attributes": attributes, "boot_id": boot_id, "warnings": [],
    }


# -- full dumps: PhysicalMemoryBlock runs ---------------------------------------------------------------------------
def _full_runs(head: bytes, meta: dict) -> List[Tuple[int, int, int]]:
    nruns, _pad, npages = _PHYSMEM.unpack_from(head, 0x88)
    if nruns == 0x45474150 or npages == 0x4547415045474150:
        raise FormatError("full dump (DumpType 1) whose PhysicalMemoryBlock is the 'PAGE' fill pattern: the run "
                          "list was never written")
    if nruns > MAX_RUNS:
        raise FormatError("full dump (DumpType 1) claims %d physical memory runs; the header has room for at "
                          "most %d" % (nruns, MAX_RUNS))
    runs, header_runs, off, total = [], [], HEADER_SIZE, 0
    for i in range(nruns):
        base, count = struct.unpack_from("<QQ", head, 0x98 + 16 * i)
        header_runs.append((base, count))
        if count:
            runs.append((base * PAGE, count * PAGE, off))
        off += count * PAGE
        total += count
    if total != npages:
        meta["warnings"].append("PhysicalMemoryBlock.NumberOfPages is %d but its runs add up to %d pages"
                                % (npages, total))
    meta["header_physical_runs"] = header_runs
    meta["first_page_offset"] = HEADER_SIZE
    return runs


# -- bitmap dumps ---------------------------------------------------------------------------------------------------
def _byte_runs(b: int) -> Tuple[Tuple[int, int], ...]:
    out, bit = [], 0
    while bit < 8:
        if (b >> bit) & 1:
            start = bit
            while bit < 8 and (b >> bit) & 1:
                bit += 1
            out.append((start, bit))
        else:
            bit += 1
    return tuple(out)


_BYTE_RUNS = tuple(_byte_runs(b) for b in range(256))
_NONZERO = re.compile(rb"[^\x00]+")
_FULL = re.compile(rb"\xff+")


def bitmap_runs(bitmap, nbits: int) -> Tuple["array.array", "array.array"]:
    """``(first_pfns, ends)`` arrays of the runs of set bits among the first ``nbits`` (bit i of byte j = PFN 8j+i;
    run k covers PFNs first_pfns[k] .. ends[k] - 1). Whole 0x00 and 0xFF bytes are skipped/merged with regular
    expressions, so only partial bytes cost a Python step; runs are kept in two arrays (16 bytes each)."""
    nbytes = (nbits + 7) // 8
    bm = bytearray(bitmap[:nbytes])
    if len(bm) < nbytes:
        raise FormatError("bitmap is truncated: %d of %d bytes" % (len(bm), nbytes))
    if nbits % 8:
        bm[-1] &= (1 << (nbits % 8)) - 1
    starts, ends = array.array("Q"), array.array("Q")

    def add(s: int, e: int) -> None:
        if ends and ends[-1] == s:
            ends[-1] = e
        else:
            starts.append(s)
            ends.append(e)

    for m in _NONZERO.finditer(bm):
        i, j = m.span()
        pos = i
        for f in _FULL.finditer(bm, i, j):
            for k in range(pos, f.start()):
                for lo, hi in _BYTE_RUNS[bm[k]]:
                    add(k * 8 + lo, k * 8 + hi)
            add(f.start() * 8, f.end() * 8)
            pos = f.end()
        for k in range(pos, j):
            for lo, hi in _BYTE_RUNS[bm[k]]:
                add(k * 8 + lo, k * 8 + hi)
    return starts, ends


def _bitmap_runs(path: str, head: bytes, size: int, meta: dict) -> Iterator[Tuple[int, int, int]]:
    sig, valid = head[0x2000:0x2004], head[0x2004:0x2008]
    first_page, present, nbits = struct.unpack_from("<QQQ", head, 0x2020)
    meta.update(bitmap_signature=sig.decode("latin-1"), first_page_offset=first_page,
                header_present_pages=present, bitmap_pages=nbits)
    where = "bitmap header at file offset 0x2000"
    if valid != b"DUMP":
        raise FormatError("%s: ValidDump is %r, expected b'DUMP' (signature %r, DumpType %d)"
                          % (where, valid, sig, meta["dump_type_value"]))
    bitmap_end = 0x2038 + (nbits + 7) // 8
    if bitmap_end > size:
        raise FormatError("%s: Pages=%d needs a %d-byte bitmap ending at 0x%x, beyond the end of the file (%d bytes)"
                          % (where, nbits, (nbits + 7) // 8, bitmap_end, size))
    if first_page < bitmap_end:
        raise FormatError("%s: FirstPage=0x%x lies inside the header/bitmap (which ends at 0x%x)"
                          % (where, first_page, bitmap_end))
    with open(path, "rb") as fh:
        fh.seek(0x2038)
        bitmap = fh.read(bitmap_end - 0x2038)
    starts, ends = bitmap_runs(bitmap, nbits)
    del bitmap
    counted = sum(ends) - sum(starts)
    if sig in BMP_SIGNATURES:
        meta["dump_type"] = ("live_kernel_bitmap" if meta["dump_type_value"] == 6 else BMP_SIGNATURES[sig])
        if counted != present:
            meta["warnings"].append("TotalPresentPages is %d but the bitmap has %d bits set: the bitmap is used"
                                    % (present, counted))
    else:
        fits = first_page + counted * PAGE <= size
        if counted != present or not fits:
            raise UnsupportedError(
                "%s: signature %r is not one of the documented 'SDMP'/'FDMP' (ValidDump 'DUMP', DumpType %d), and "
                "the structure does not confirm the bitmap layout (bits set %d, TotalPresentPages %d, page data "
                "0x%x..0x%x, file %d bytes)" % (where, sig, meta["dump_type_value"], counted, present, first_page,
                                                first_page + counted * PAGE, size))
        meta["dump_type"] = "bitmap_unknown_signature"
        meta["warnings"].append("bitmap header signature %r is not a documented value ('SDMP'/'FDMP'); accepted "
                                "because the bitmap population (%d) equals TotalPresentPages and the page data fits "
                                "the file" % (sig, counted))
    return _stream(starts, ends, first_page)


def _stream(starts, ends, first_page: int) -> Iterator[Tuple[int, int, int]]:
    off = first_page
    for s, e in zip(starts, ends):
        yield s * PAGE, (e - s) * PAGE, off
        off += (e - s) * PAGE


# -- RDMP dumps (DumpType 8, 9, 0xA) ----------------------------------------------------------------------------------
def _rdmp_runs(path: str, head: bytes, size: int, meta: dict) -> List[Tuple[int, int, int]]:
    marker, sig, valid, _unused, metadata_size, first_page = struct.unpack_from("<I4s4sIQQ", head, 0x2000)
    where = "RDMP header at file offset 0x2000"
    meta.update(first_page_offset=first_page, rdmp_metadata_size=metadata_size)
    if (marker, sig, valid) != (0x40, b"RDMP", b"DUMP"):
        raise FormatError("%s: marker/signature/ValidDump are 0x%x/%r/%r, expected 0x40/b'RDMP'/b'DUMP'"
                          % (where, marker, sig, valid))
    if first_page != 0x2020 + metadata_size:
        raise FormatError("%s: FirstPageOffset 0x%x does not follow the metadata (0x2020 + MetadataSize 0x%x)"
                          % (where, first_page, metadata_size))
    if first_page > size or (first_page - 0x2030) % 16:
        raise FormatError("%s: the PFN range table 0x2030..0x%x does not fit the file (%d bytes) or is not a "
                          "multiple of 16 bytes" % (where, first_page, size))
    complete = meta["dump_type_value"] == 10
    total_pages = struct.unpack_from("<Q", head, 0x2028)[0] if complete else None
    if complete:
        meta["rdmp_total_pages"] = total_pages
    with open(path, "rb") as fh:
        fh.seek(0x2030)
        table = fh.read(first_page - 0x2030)
    runs, off, pages = [], first_page, 0
    for i in range(len(table) // 16):
        if complete and pages >= total_pages:
            break
        pfn, count = struct.unpack_from("<QQ", table, 16 * i)
        if pfn == 0:  # the range list ends at a zero PFN (kdmp-parser)
            break
        if count == 0:
            raise FormatError("%s: PFN range %d (PFN 0x%x) has zero pages" % (where, i, pfn))
        runs.append((pfn * PAGE, count * PAGE, off))
        off += count * PAGE
        pages += count
    if complete and pages != total_pages:
        meta["warnings"].append("TotalNumberOfPages is %d but the PFN ranges hold %d pages" % (total_pages, pages))
    return runs


def open_windump(name: str, path: str):
    """``(PhysicalRunLayer, metadata)`` for a 64-bit crash/live dump; see the module docstring."""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(0x2040)
    if head[:8] == SIG32:
        raise UnsupportedError("%s is a 32-bit Windows crash dump ('PAGEDUMP'): only 64-bit ('PAGEDU64') dumps are "
                               "supported" % path)
    if head[:8] != SIG64:
        raise FormatError("%s is not a 64-bit Windows crash dump (signature %r, expected b'PAGEDU64')"
                          % (path, head[:8]))
    if len(head) < HEADER_SIZE:
        raise FormatError("%s: crash dump header is truncated (%d of 8192 bytes)" % (path, len(head)))
    meta = parse_header(head)
    dt = meta["dump_type_value"]
    if dt == 1:
        runs = _full_runs(head, meta)
    elif dt in (5, 6):
        if len(head) < 0x2038:
            raise FormatError("%s: DumpType %d but the bitmap header at 0x2000 is truncated" % (path, dt))
        runs = _bitmap_runs(path, head, size, meta)
    elif dt in (8, 9, 10):
        if len(head) < 0x2030:
            raise FormatError("%s: DumpType %d but the RDMP header at 0x2000 is truncated" % (path, dt))
        runs = _rdmp_runs(path, head, size, meta)
    elif dt == 4:
        raise UnsupportedError("%s is a triage/mini kernel dump (DumpType 4): it holds selected structures, not "
                               "physical memory pages" % path)
    elif dt == 2:
        raise UnsupportedError("%s is a legacy kernel summary dump (DumpType 2, pre-Windows 8): this layout is not "
                               "supported (types 1, 5, 6, 8, 9 and 10 are)" % path)
    else:
        raise UnsupportedError("%s: unknown crash dump DumpType 0x%x (supported: 1 full, 5 bitmap, 6 live kernel "
                               "bitmap, 8/9/0xA RDMP)" % (path, dt))
    layer, warnings = file_runs(name, path, runs, "windump")
    meta["warnings"] += warnings
    meta["truncated"] = bool(warnings)
    meta["physical_runs"] = list(layer.ranges())
    meta["present_pages"] = layer.size // PAGE
    return layer, meta
