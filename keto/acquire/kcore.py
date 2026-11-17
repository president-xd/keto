"""``keto acquire --method kcore``: physical RAM of a running Linux kernel (WSL2 included) through
``/proc/kcore``, the same source AVML uses, plus what is needed to analyse it offline: the kernel's BTF,
the symbols the host-memory plugins use, the banner and the address-translation parameters.

Pages that read as all zero are not stored (``zero_pages_omitted``); the analysis layer reads them back as
zeros. Runs of data separated by fewer than ``GAP_PAGES`` zero pages are kept as one segment.
"""

from __future__ import annotations

import hashlib
import os
import platform
import time

from keto.formats.container import ContainerWriter
from keto.framework.exceptions import RequirementError
from keto.hostmem import btf as btf_mod
from keto.hostmem.linux import START_KERNEL_MAP, WANTED_SYMBOLS, KcoreReader, KernelMemory, parse_kallsyms

PAGE = 4096
GAP_PAGES = 8
CHUNK = 16 << 20
ZERO = bytes(PAGE)


def _runs(kc: KcoreReader, vaddr: int, size: int):
    """Yield ``(offset, bytes)`` runs of non-zero pages inside one RAM segment."""
    run_start, run = None, []
    gap = 0
    pos = 0
    while pos < size:
        n = min(CHUNK, size - pos)
        data = kc.read(vaddr + pos, n)
        for i in range(0, n, PAGE):
            page = data[i:i + PAGE]
            if page == ZERO[:len(page)]:
                if run_start is not None:
                    gap += 1
                    run.append(page)
                    if gap > GAP_PAGES:
                        del run[-gap:]
                        yield run_start, b"".join(run)
                        run_start, run, gap = None, [], 0
                continue
            if run_start is None:
                run_start = pos + i
            gap = 0
            run.append(page)
        pos += n
    if run_start is not None:
        if gap:
            del run[-gap:]
        yield run_start, b"".join(run)


def acquire_kcore(args, out, base_metadata) -> int:
    if not os.path.exists("/proc/kcore"):
        raise RequirementError("kcore method needs Linux with /proc/kcore (CONFIG_PROC_KCORE)")
    try:
        kc = KcoreReader()
    except PermissionError:
        raise RequirementError("reading /proc/kcore needs root (e.g. 'wsl -u root' or sudo)")
    with open("/proc/kallsyms", "r") as fh:
        all_syms = parse_kallsyms(fh.read())
    if "init_task" not in all_syms:
        raise RequirementError("/proc/kallsyms shows no addresses (kptr_restrict): run as root")
    syms = {k: all_syms[k] for k in WANTED_SYMBOLS if k in all_syms}
    btf_blob = b""
    if os.path.exists("/sys/kernel/btf/vmlinux"):
        with open("/sys/kernel/btf/vmlinux", "rb") as fh:
            btf_blob = fh.read()
    if not btf_blob:
        raise RequirementError("kernel has no BTF (/sys/kernel/btf/vmlinux): struct layouts cannot be recorded")
    km = KernelMemory(btf_mod.Btf(btf_blob), syms, kcore=kc)
    text = syms.get("_text")
    seg = next((s for s in kc.segments if text and s[0] <= text < s[0] + s[1]), None)
    phys_base = (seg[3] + (text - seg[0])) - (text - START_KERNEL_MAP) if seg else None
    ranges = kc.ram_ranges(km.page_offset_base)
    if not ranges:
        raise RequirementError("no direct-map RAM segments in /proc/kcore")
    with open("/proc/version", "r") as fh:
        banner = fh.read().strip()
    meta = base_metadata
    meta["kernel"] = {"os": "linux", "arch": "x86_64", "banner": banner, "release": platform.release(),
                      "symbols": {k: "0x%x" % v for k, v in syms.items()},
                      "phys_base": "0x%x" % phys_base if phys_base is not None else None,
                      "page_offset_base": "0x%x" % km.page_offset_base, "l5": km.l5,
                      "zero_pages_omitted": True, "btf_sha256": hashlib.sha256(btf_blob).hexdigest(),
                      "ram_ranges": [{"start": "0x%x" % p, "size": s} for p, s, _v in ranges]}
    meta["acquisition"]["notes"] = ("physical RAM through /proc/kcore (direct-map segments); all-zero pages "
                                    "omitted; kernel BTF and %d symbols stored for offline analysis" % len(syms))
    writer = ContainerWriter(args.out, meta)
    t0 = time.time()
    stored = total = 0
    try:
        writer.add_segment("kbtf", 0, btf_blob)
        for paddr, size, vaddr in ranges:
            total += size
            for off, data in _runs(kc, vaddr, size):
                writer.add_segment("sysmem", paddr + off, data)
                stored += len(data)
    finally:
        writer.metadata = meta
        writer.close()
        kc.close()
    out.write("kernel %s: %d MiB RAM in %d range(s), %d MiB non-zero stored in %d segment(s) -> %s in %.1fs\n" % (
        platform.release(), total >> 20, len(ranges), stored >> 20, len(writer.segments) - 1, args.out,
        time.time() - t0))
    return 0
