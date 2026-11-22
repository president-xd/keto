"""Automagic: decide which architecture profile applies, without user input
where possible (the equivalent of Volatility's symbol-table finder).

Evidence, strongest first:
  1. ``--profile`` on the command line
  2. container metadata: chipset id (NV_PMC_BOOT_0), NVML architecture id,
     CUDA compute capability, device name
  3. live NVML data (when analysing a live system or a snapshot)
  4. banners in the image (GPU product names)
  5. structures in the image: engine class ids bound with SET_OBJECT (each
     class id belongs to one or two generations), the version byte of launch
     descriptors (QMDs), and which RAMIN/RAMFC layout yields valid instance
     blocks (Blackwell moved the RAMFC signature from 0x10 to 0x38)
  6. fallback: the Ampere/Ada (VER2, Volta+ layout) profile, with a warning
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Dict, List, Tuple

from keto.framework.profiles import Profile

log = logging.getLogger("keto.automagic")
#: a GPU product name as drivers print it: "NVIDIA " and up to 7 name words (greedy, stops at NUL/punctuation),
#: e.g. "NVIDIA GeForce RTX 4050 Laptop GPU", "NVIDIA H100 80GB HBM3"; or nvidia-smi's bare "Tesla <model>"
#: ("Tesla V100-SXM2-16GB": a letter+digits model number, so prose such as "Tesla Model S" does not match)
NAME_RE = re.compile(rb"NVIDIA (?:GeForce |Quadro |Tesla |RTX |TITAN |DGX )?[A-Za-z0-9][\w\-]*(?: [\w\-]+){0,6}"
                     rb"|Tesla [A-Z]\d{1,4}[\w\-]*")


def _from_device(reg, dev: dict):
    chip = dev.get("chipset")
    if chip is not None:
        p = reg.by_chipset(int(chip, 16) if isinstance(chip, str) else int(chip))
        if p:
            return p, "chipset 0x%x from image metadata" % (int(chip, 16) if isinstance(chip, str) else chip)
    arch = dev.get("nvml_arch")
    if isinstance(arch, dict):
        arch = arch.get("id")
    if isinstance(arch, int):
        p = reg.by_nvml_arch(arch)
        if p:
            return p, "NVML architecture id %d" % arch
    cc = dev.get("compute_capability")
    if isinstance(cc, str):
        p = reg.by_compute_capability(cc)
        if p:
            return p, "compute capability %s" % cc
    name = dev.get("name")
    if isinstance(name, str):
        p = reg.by_device_name(name)
        if p:
            return p, "device name %r" % name
    return None, ""


QMD_SCAN_LIMIT = 256 << 20  # launch descriptors are only a tie-breaker; bound the 256-byte-stride scan


def _vote(votes, why, names, weight, reason):
    names = sorted(names)
    for n in names:
        votes[n] += weight / len(names)
        why[n].append(reason)


def _from_structures(ctx, reg) -> Tuple[object, str]:
    """Vote for a profile from GPU structures found in the VRAM image itself."""
    from keto.framework.layers import BytesLayer
    from keto.framework.scanners import AnchoredScanner, byte_prefilter, scan, scan_aligned_u32
    from keto.gpu import pushbuf, qmd as qmd_fmt
    from keto.gpu.ramin import parse_instance_block
    layer = ctx.layers.get("vram")
    if layer is None:
        return None, ""
    votes: Dict[str, float] = defaultdict(float)
    why: Dict[str, List[str]] = defaultdict(list)
    profiles = list(reg.profiles.values())
    # 1. engine class ids: the strongest structural evidence (a compute class id names one generation)
    by_class = defaultdict(set)
    for p in profiles:
        for cid in p.classes.values():
            by_class[cid].add(p.name)
    sc = AnchoredScanner([b"\x01\x20", b"\x01\x60", b"\x01\xa0"], pushbuf.SET_OBJECT_RE, before=2, after=8)
    sc.alignment = 4
    seen = set()
    for _, m in scan(layer, sc):
        cid = int.from_bytes(m.group(1), "little")
        if cid in by_class and cid not in seen:
            seen.add(cid)
            _vote(votes, why, by_class[cid], 3.0, "SET_OBJECT %s" % reg.classes.class_name(cid))
    # 2. RAMFC signature offset / layout: count instance blocks that validate under each layout
    layouts = defaultdict(list)
    for p in profiles:
        layouts[p.doc.get("layout")].append(p)
    best, best_n = None, 0
    for lname, ps in layouts.items():
        p, fc = ps[0], ps[0].ramfc
        mask, value = fc.get("signature_mask", 0xFFFF), fc.get("signature_value", 0xFACE)
        n = 0
        for pa, _ in scan_aligned_u32(layer, fc["signature"], 4096, lambda v: (v & mask) == value,
                                      prefilter=byte_prefilter(fc["signature"], mask, value)):
            if parse_instance_block(layer, pa, p, ctx.vram_size).valid:
                n += 1
        if n > best_n:
            best, best_n = lname, n
    if best is not None:
        sig = layouts[best][0].ramfc["signature"]
        same_sig = [p.name for p in profiles if p.ramfc["signature"] == sig]
        _vote(votes, why, same_sig, 2.0, "%d instance block(s) with the RAMFC signature at 0x%x" % (best_n, sig))
    # 3. launch descriptor versions (the version byte is in the descriptor)
    gen_of = defaultdict(set)
    for fam, ver in qmd_fmt.CLASS_DEFAULT.items():
        gen_of[ver].add(fam.split("_")[0])
    head = BytesLayer("head", layer.read(layer.minimum_address, min(layer.size, QMD_SCAN_LIMIT), pad=True))
    versions = set()
    for woff, mask, values in qmd_fmt.scan_signatures():
        for off, _ in scan_aligned_u32(head, woff, qmd_fmt.QMD_SIZE, lambda v: (v & mask) in values,
                                       prefilter=byte_prefilter(woff, mask, values)):
            raw = head.read(off, qmd_fmt.MAX_QMD_SIZE, pad=True)
            q = qmd_fmt.decode(raw) if qmd_fmt.quick_plausible(raw) else None
            if q is not None and q.plausible():
                versions.add(q.version)
    for v in sorted(versions):
        names = {n for n in gen_of.get(v, ()) if n in reg.profiles}
        if names:
            _vote(votes, why, names, 1.0, "QMD %s" % v.upper())
    if not votes:
        return None, ""
    ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
    name, score = ranked[0]
    tied = [n for n, s in ranked if abs(s - score) < 1e-9]
    note = "" if len(tied) == 1 else "; tied with %s" % ", ".join(tied[1:])
    return reg.get(name), "structures in the image: %s%s" % ("; ".join(why[name]), note)


def _cheap_evidence(ctx, reg) -> Tuple[object, str]:
    """Profile evidence that costs no image-wide scan: container metadata, the live/snapshot NVML view, and GPU
    name banners in the first 64 MiB of the image."""
    dev = ctx.metadata.get("device") or {}
    p, why = _from_device(reg, dev)
    if p:
        return p, why
    if ctx.has_live():
        try:
            nv = ctx.live.nvml()
            for d in nv.get("devices", []):
                arch = d.get("architecture")
                if isinstance(arch, dict):
                    p, why = _from_device(reg, {"nvml_arch": arch.get("id"), "name": d.get("name"),
                                                "compute_capability": d.get("compute_capability")})
                    if p:
                        return p, why + " (live)"
        except Exception as exc:  # live source problems must not block image analysis
            log.debug("live profile detection failed: %s", exc)
    if ctx.has_image():
        layer = ctx.primary
        head = layer.read(layer.minimum_address, min(layer.size, 64 << 20), pad=True)
        for m in NAME_RE.finditer(head):
            p = reg.by_device_name(m.group().decode("ascii", "replace"))
            if p:
                return p, "GPU name banner %r in image" % m.group().decode("ascii", "replace")
    return None, ""


def choose_profile(ctx, requested=None) -> Tuple[Profile, str]:
    reg = ctx.registry
    if requested:
        chosen = reg.get(requested)
        p, why = _cheap_evidence(ctx, reg)
        if p is not None and p.name != chosen.name:
            log.warning("--profile %s contradicts the evidence (%s points to %s): structures will be decoded "
                        "with the wrong layout and results may be wrong", chosen.name, why, p.name)
            return chosen, "selected with --profile, CONTRADICTING %s (%s)" % (p.name, why)
        return chosen, "selected with --profile"
    p, why = _cheap_evidence(ctx, reg)
    if p:
        return p, why
    if ctx.has_image():
        try:
            p, why = _from_structures(ctx, reg)
        except Exception as exc:  # structural voting is best effort
            log.debug("structural profile detection failed: %s", exc)
            p = None
        if p:
            return p, why
    fallback = reg.get("ada") if "ada" in reg.profiles else next(iter(reg.profiles.values()))
    log.warning("no architecture evidence found; assuming profile %s (override with --profile)", fallback.name)
    return fallback, "fallback (no evidence; VER2 MMU / Volta+ layout assumed)"
