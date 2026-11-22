"""Builds the KernelMemory for a plugin run from whatever host-memory evidence the context holds.

Order of preference:
  1. a ``.keto`` host-RAM container from ``keto acquire --method kcore`` (BTF, symbols and translation
     parameters are inside it), given with ``-f`` or ``--host-image``;
  2. any physical RAM image (LiME from AVML/LiME, raw) plus ``--btf`` and ``--kallsyms`` files taken from the
     same boot;
  3. the running Linux kernel through ``/proc/kcore`` (root), ``/sys/kernel/btf/vmlinux`` and ``/proc/kallsyms``.
"""

from __future__ import annotations

import os
from typing import Optional

from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Requirement
from keto.hostmem import btf as btf_mod
from keto.hostmem.linux import KcoreReader, KernelMemory, parse_kallsyms

HOST_REQS = [Requirement("btf", str, None, "BTF of the imaged kernel (copy of /sys/kernel/btf/vmlinux, same boot)"),
             Requirement("kallsyms", str, None, "kallsyms or System.map of the imaged kernel (same boot)"),
             Requirement("kcore", bool, False, "analyse the running kernel through /proc/kcore (root)")]


def _kernel_meta(ctx) -> Optional[dict]:
    for meta in (getattr(ctx, "host_metadata", None) or {}, ctx.metadata or {}):
        if meta.get("kernel"):
            return meta["kernel"]
    return None


def _pad_gaps(meta: Optional[dict]):
    """Omitted pages read as zeros, but only inside the RAM that was acquired (the ``acquired_ranges`` of a
    limited acquisition, else ``ram_ranges``): anything else is not in the image."""
    if not (meta and meta.get("zero_pages_omitted")):
        return False
    ranges = meta.get("acquired_ranges")
    if ranges is None:
        ranges = meta.get("ram_ranges")
    if ranges is None:
        return True
    return [(int(r["start"], 16), int(r["size"])) for r in ranges]


def kernel_memory(ctx, opts: dict) -> KernelMemory:
    key = ("kernel_memory", opts.get("btf"), opts.get("kallsyms"), bool(opts.get("kcore")))
    if key in ctx.cache:
        return ctx.cache[key]
    phys = ctx.layers.get("sysmem") or ctx.layers.get("physical")  # --host-image / -f container, or -f LiME
    meta = _kernel_meta(ctx)
    if opts.get("kcore"):
        km = _live()
    elif phys is not None and (opts.get("btf") or opts.get("kallsyms")):
        if not (opts.get("btf") and opts.get("kallsyms")):
            raise RequirementError("a host RAM image needs both --btf and --kallsyms from the same boot")
        with open(opts["kallsyms"], "r", encoding="utf-8", errors="replace") as fh:
            syms = parse_kallsyms(fh.read())
        km = KernelMemory(btf_mod.load(opts["btf"]), syms, phys=phys, pad_gaps=_pad_gaps(meta))
    elif phys is not None and meta:
        blob_layer = ctx.layers.get("kbtf")
        if blob_layer is None:
            raise RequirementError("host container has kernel metadata but no BTF segment")
        blob = blob_layer.read(blob_layer.minimum_address, blob_layer.maximum_address + 1 - blob_layer.minimum_address)
        syms = {k: int(v, 16) if isinstance(v, str) else int(v) for k, v in meta["symbols"].items()}
        recorded = meta.get("phys_base")
        km = KernelMemory(btf_mod.Btf(blob), syms, phys=phys, pad_gaps=_pad_gaps(meta),
                          phys_base_hint=int(recorded, 16) if recorded is not None else None)
        if recorded is not None and int(recorded, 16) != km.phys_base:
            km.notes.append("WARNING: phys_base found in the image (0x%x) differs from the value recorded at "
                            "acquisition (%s)" % (km.phys_base, recorded))
    elif phys is not None:
        raise RequirementError("host RAM image without kernel metadata: give --btf and --kallsyms from the "
                               "same boot (or acquire with 'keto acquire --method kcore')")
    else:
        raise RequirementError("no host memory: use -f/--host-image with a host RAM image, or --kcore as root")
    ctx.cache[key] = km
    return km


def _live() -> KernelMemory:
    if not os.path.exists("/proc/kcore"):
        raise RequirementError("--kcore needs a Linux kernel with /proc/kcore (CONFIG_PROC_KCORE)")
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        raise RequirementError("--kcore needs kernel BTF (/sys/kernel/btf/vmlinux, CONFIG_DEBUG_INFO_BTF)")
    try:
        kc = KcoreReader()
    except PermissionError:
        raise RequirementError("/proc/kcore needs root")
    with open("/proc/kallsyms", "r") as fh:
        syms = parse_kallsyms(fh.read())
    if "init_task" not in syms:
        raise RequirementError("/proc/kallsyms shows no addresses (kptr_restrict): run as root")
    return KernelMemory(btf_mod.load("/sys/kernel/btf/vmlinux"), syms, kcore=kc)
