"""Shared, cached analyses that many plugins build on.

* ``instance_blocks``   signature scan for channel instance blocks (RAMFC 0xFACE)
* ``runlists``          signature scan for Volta+ runlists (TSG headers)
* ``address_spaces``    one GMMU layer per distinct page directory (main + subcontexts)
* ``cubins`` / ``fatbins`` / ``ptx_modules``   CUDA code containers anywhere in the image
* ``kernel_code``       where each known kernel's machine code sits in VRAM
* ``channel_commands``  GPFIFO -> pushbuffer -> methods -> events for every channel
* ``launches``          compute launches with decoded QMDs and resolved kernels
"""

from __future__ import annotations

import logging
import os
import struct
from typing import Dict, List, Optional, Tuple

from keto.formats import cubin as cubin_fmt
from keto.formats import fatbin as fatbin_fmt
from keto.formats import ptx as ptx_fmt
from keto.formats.elf import elf_extent
from keto.framework.exceptions import UnsupportedError
from keto.framework.layers import DataLayer
from keto.framework.scanners import BytesScanner, RegexScanner, scan, scan_aligned_u32
from keto.gpu import pushbuf, qmd as qmd_fmt, sass
from keto.gpu.gmmu import VID, GmmuLayer, GmmuWalker, build_reverse_index
from keto.gpu.ramin import InstanceBlock, parse_instance_block, read_userd
from keto.gpu.runlist import Runlist, scan_runlists

log = logging.getLogger("keto.discovery")


# ------------------------------------------------------------------------------------------
# channels
# ------------------------------------------------------------------------------------------
def instance_blocks(ctx, include_invalid: bool = False) -> List[InstanceBlock]:
    key = "instance_blocks_all" if include_invalid else "instance_blocks"

    def build():
        layer = ctx.require_vram()
        prof = ctx.profile
        fc = prof.ramfc
        mask, value = fc.get("signature_mask", 0xFFFF), fc.get("signature_value", 0xFACE)
        out = []
        for pa, _ in scan_aligned_u32(layer, fc["signature"], 4096, lambda v: (v & mask) == value):
            ib = parse_instance_block(layer, pa, prof, ctx.vram_size)
            if ib.valid or include_invalid:
                out.append(ib)
        if "userd_lo" not in fc and not include_invalid:
            # Ampere+: RAMFC no longer records USERD; the runlist entry is the only place that does
            for rl in _scan_runlists(ctx, {ib.pa for ib in out}):
                for c in rl.channels():
                    for ib in out:
                        if ib.pa == c.inst_addr and c.userd_addr:
                            ib.userd_addr, ib.userd_aperture = c.userd_addr, c.userd_aperture
                            ib.reasons.append("USERD from runlist")
        for ib in out:
            read_userd(ib, ctx.aperture_layers(), prof)
        return out

    return ctx.cached(key, build)


def _scan_runlists(ctx, known) -> List[Runlist]:
    fmt = ctx.profile.runlist.get("format")
    if "runlists" not in ctx.cache:
        if fmt == "gk104":
            # Kepler entries hold only a CHID: tie them to instance blocks through the CHID in each RAMFC
            from keto.gpu.runlist import scan_runlists_gk104
            chid_inst: Dict[int, Optional[int]] = {}
            for ib in instance_blocks(ctx):
                if ib.chid_hint is not None and ib.pa in known:
                    chid_inst[ib.chid_hint] = None if ib.chid_hint in chid_inst else ib.pa
            if not chid_inst:
                raise UnsupportedError("Kepler runlists hold only channel ids and no instance block carries a CHID "
                                       "in this layout - use nvidia.chanscan")
            ctx.cache["runlists"] = scan_runlists_gk104(ctx.require_vram(), chid_inst, ctx.vram_size)
        elif fmt == "gm107":
            from keto.gpu.runlist import scan_runlists_gm107
            ctx.cache["runlists"] = scan_runlists_gm107(ctx.require_vram(), known, ctx.vram_size)
        else:
            ctx.cache["runlists"] = scan_runlists(ctx.require_vram(), ctx.vram_size, known)
    return ctx.cache["runlists"]


def runlists(ctx) -> List[Runlist]:
    if "runlists" in ctx.cache:
        return ctx.cache["runlists"]
    return _scan_runlists(ctx, {ib.pa for ib in instance_blocks(ctx)})


# ------------------------------------------------------------------------------------------
# address spaces
# ------------------------------------------------------------------------------------------
class AddressSpace:
    def __init__(self, name: str, pdb: int, aperture: str, fmt: str, big_page_size: int, layer: GmmuLayer):
        self.name, self.pdb, self.aperture, self.fmt = name, pdb, aperture, fmt
        self.big_page_size, self.layer = big_page_size, layer
        self.sources: List[Tuple[int, str]] = []  # (instance block pa, label)
        self._rindex = None

    @property
    def walker(self) -> GmmuWalker:
        return self.layer.walker

    def mappings(self):
        return self.layer.mappings()

    def reverse_index(self):
        if self._rindex is None:
            self._rindex = build_reverse_index(self.mappings())
        return self._rindex

    def translate(self, va: int):
        return self.layer.translate(va)

    def __repr__(self):
        return "<AddressSpace %s pdb=%s:0x%x %s>" % (self.name, self.aperture, self.pdb, self.fmt)


def make_address_space(ctx, pdb: int, aperture: str = VID, big_page_size: int = 65536,
                       fmt: Optional[str] = None) -> AddressSpace:
    fmt = fmt or ctx.profile.mmu_format
    if ctx.cache.get("big_page_override"):
        big_page_size = ctx.cache["big_page_override"]
    name = "as_%x" % pdb
    walker = GmmuWalker(ctx.aperture_layers(), pdb, fmt, aperture, big_page_size, ctx.vram_size)
    return AddressSpace(name, pdb, aperture, fmt, big_page_size, GmmuLayer(name, walker))


def address_spaces(ctx) -> List[AddressSpace]:
    def build():
        spaces: Dict[Tuple[str, int], AddressSpace] = {}
        for pdb in ctx.cache.get("extra_pdbs", []):
            spaces[(VID, pdb)] = make_address_space(ctx, pdb)
            spaces[(VID, pdb)].sources.append((None, "--pdb"))
        try:
            ibs = instance_blocks(ctx)
        except UnsupportedError:
            ibs = []
        prof = ctx.profile
        for ib in ibs:
            for label, ap, pdb, ver2, big in ib.address_spaces():
                if ap is None or not pdb:
                    continue
                fmt = prof.mmu_format
                if fmt == "v2" and not ver2:
                    fmt = "v1"  # Pascal instance blocks may still select VER1 (NV_RAMIN_USE_VER2_PT_FORMAT = 0)
                if prof.name == "kepler":
                    # before GM20x the big page size is a global register (MMIO 0x100c80), not in the instance
                    # block: use the profile default (128 KiB) unless --big-page overrides it
                    big = prof.big_page_sizes[0]
                key = (ap, pdb)
                if key not in spaces:
                    spaces[key] = make_address_space(ctx, pdb, ap, big, fmt)
                spaces[key].sources.append((ib.pa, label))
        for layer_name in list(ctx.layers):
            if layer_name.startswith("as_"):
                del ctx.layers[layer_name]
        out = sorted(spaces.values(), key=lambda a: a.pdb)
        for a in out:
            ctx.layers[a.name] = a.layer
        return out

    return ctx.cached("address_spaces", build)


def address_space_of(ctx, ib: InstanceBlock, label: str = "main") -> Optional[AddressSpace]:
    for a in address_spaces(ctx):
        if (ib.pa, label) in a.sources:
            return a
    return None


def reverse_lookup_all(ctx, pa: int) -> List[Tuple[AddressSpace, int, object]]:
    """Every (address space, VA, mapping) that maps VRAM physical address ``pa``."""
    from keto.gpu.gmmu import reverse_lookup
    out = []
    for a in address_spaces(ctx):
        for m in reverse_lookup(a.reverse_index(), pa):
            out.append((a, m.va + (pa - m.pa), m))
    return out


# ------------------------------------------------------------------------------------------
# CUDA code containers
# ------------------------------------------------------------------------------------------
class FoundCubin:
    def __init__(self, layer: str, offset: int, size: int, cubin, error: Optional[str] = None, source: str = "scan"):
        self.layer, self.offset, self.size, self.cubin, self.error, self.source = layer, offset, size, cubin, error, source

    @property
    def kernels(self):
        return self.cubin.kernels if self.cubin else []


def _scan_cubins(layer: DataLayer, source: str = "scan") -> List[FoundCubin]:
    out = []
    for off, _ in scan(layer, BytesScanner(b"\x7fELF\x02\x01")):
        head = layer.read(off, 64, pad=True)
        if struct.unpack_from("<H", head, 18)[0] != cubin_fmt.EM_CUDA:
            continue
        window = layer.read(off, min(16 << 20, layer.maximum_address + 1 - off), pad=True)
        size = elf_extent(window) or 64
        data = window[:size]
        try:
            out.append(FoundCubin(layer.name, off, size, cubin_fmt.parse_cubin(data), source=source))
        except Exception as exc:
            out.append(FoundCubin(layer.name, off, size, None, str(exc), source=source))
    return out


def scan_layers(ctx) -> List[DataLayer]:
    """Physical layers worth scanning for artefacts (primary first, then host memory)."""
    out = [ctx.primary] if ctx.has_image() else []
    if "sysmem" in ctx.layers and ctx.layers["sysmem"] is not ctx.primary:
        out.append(ctx.layers["sysmem"])
    return out


def cubins(ctx) -> List[FoundCubin]:
    def build():
        found = []
        for layer in scan_layers(ctx):
            found += _scan_cubins(layer)
        # cubins embedded in fatbins (decompressed)
        for fb in fatbins(ctx):
            for e in fb["fatbin"].entries:
                if e.kind == fatbin_fmt.KIND_ELF and e.data:
                    try:
                        found.append(FoundCubin(fb["layer"], e.offset, len(e.data), cubin_fmt.parse_cubin(e.data),
                                                source="fatbin%s" % (" (%s)" % e.compression if e.compressed else "")))
                    except Exception as exc:
                        found.append(FoundCubin(fb["layer"], e.offset, len(e.data), None, str(exc), source="fatbin"))
        for path in ctx.cache.get("reference_files", []):
            found += reference_cubins(path)
        return found

    return ctx.cached("cubins", build)


def reference_cubins(path: str) -> List[FoundCubin]:
    """Cubins from an on-disk reference (a cubin, a fatbin, or any binary embedding fatbins)."""
    from keto.framework.layers import BytesLayer
    with open(path, "rb") as fh:
        data = fh.read()
    layer = BytesLayer("ref:" + os.path.basename(path), data)
    found = _scan_cubins(layer, source="reference")
    for off, _ in scan(layer, BytesScanner(fatbin_fmt.FATBIN_MAGIC_BYTES)):
        fb = fatbin_fmt.parse_fatbin(data[off:], off)
        for e in (fb.entries if fb else []):
            if e.kind == fatbin_fmt.KIND_ELF and e.data:
                try:
                    found.append(FoundCubin(layer.name, e.offset, len(e.data), cubin_fmt.parse_cubin(e.data),
                                            source="reference-fatbin"))
                except Exception:
                    pass
    return found


def fatbins(ctx) -> List[dict]:
    def build():
        out = []
        for layer in scan_layers(ctx):
            for off, _ in scan(layer, BytesScanner(fatbin_fmt.FATBIN_MAGIC_BYTES)):
                head = layer.read(off, 16, pad=True)
                size = struct.unpack_from("<Q", head, 8)[0]
                if not 0 < size < (256 << 20):
                    continue
                data = layer.read(off, min(16 + size, layer.maximum_address + 1 - off), pad=True)
                fb = fatbin_fmt.parse_fatbin(data, off)
                if fb:
                    out.append({"layer": layer.name, "offset": off, "fatbin": fb})
        return out

    return ctx.cached("fatbins", build)


def fatbin_wrappers(ctx) -> List[dict]:
    def build():
        out = []
        for layer in scan_layers(ctx):
            for off, _ in scan(layer, BytesScanner(fatbin_fmt.WRAPPER_MAGIC_BYTES)):
                w = fatbin_fmt.parse_wrapper(layer.read(off, 24, pad=True))
                if w:
                    w.update(layer=layer.name, offset=off)
                    out.append(w)
        return out

    return ctx.cached("fatbin_wrappers", build)


def ptx_modules(ctx) -> List[dict]:
    def build():
        out = []
        seen = set()
        for layer in scan_layers(ctx):
            for off, m in scan(layer, RegexScanner(ptx_fmt.VERSION_RE, max_length=32)):
                window_start = max(layer.minimum_address, off - 4096)
                data = layer.read(window_start, min(4 << 20, layer.maximum_address + 1 - window_start), pad=True)
                span = ptx_fmt.carve(data, off - window_start)
                if not span:
                    continue
                start, end = window_start + span[0], window_start + span[1]
                if (layer.name, start) in seen:
                    continue
                seen.add((layer.name, start))
                mod = ptx_fmt.parse(data[span[0]:span[1]])
                if mod.target is None and not mod.entries:
                    continue
                out.append({"layer": layer.name, "offset": start, "size": end - start, "module": mod,
                            "source": "scan"})
        for fb in fatbins(ctx):
            for e in fb["fatbin"].entries:
                if e.kind == fatbin_fmt.KIND_PTX and e.data:
                    text = e.data.split(b"\x00", 1)[0]
                    out.append({"layer": fb["layer"], "offset": e.offset, "size": len(text),
                                "module": ptx_fmt.parse(text), "source": "fatbin"})
        return out

    return ctx.cached("ptx_modules", build)


# ------------------------------------------------------------------------------------------
# kernel code location
# ------------------------------------------------------------------------------------------
class KernelCode:
    def __init__(self, pa, size, kernel, found, kind, match_ratio):
        self.pa, self.size, self.kernel, self.found = pa, size, kernel, found
        self.kind, self.match_ratio = kind, match_ratio


def _trim_padding(text: bytes) -> bytes:
    while len(text) >= 16 and text[-16:] in (sass.NOP_INSN, b"\x00" * 16):
        text = text[:-16]
    return text


def kernel_code(ctx) -> List[KernelCode]:
    """Locate every known kernel's machine code inside the VRAM image."""

    def build():
        vram = ctx.vram
        if vram is None:
            return []
        sigs: Dict[bytes, list] = {}
        for fc in cubins(ctx):
            for k in fc.kernels:
                body = _trim_padding(k.text)
                if len(body) < 32:
                    continue
                sigs.setdefault(body[:48], []).append((fc, k, body))
        if not sigs:
            return []
        from keto.framework.scanners import MultiStringScanner
        hits = []
        for off, m in scan(vram, MultiStringScanner(list(sigs))):
            sig = m.group()
            best = None
            for fc, k, body in sigs.get(sig, []):
                mem = vram.read(off, len(body), pad=True)
                same = sum(1 for a, b in zip(mem, body) if a == b) / len(body)
                if best is None or same > best[0] or (same == best[0] and len(body) > len(best[3])):
                    best = (same, fc, k, body)
            if best is None:
                continue
            same, fc, k, body = best[0], best[1], best[2], best[3]
            inside = fc.layer == vram.name and fc.source == "scan" and fc.offset <= off < fc.offset + fc.size
            hits.append(KernelCode(off, len(body), k, fc, "cubin-section" if inside else "loaded-copy", same))
        return hits

    return ctx.cached("kernel_code", build)


def code_at(ctx, pa: int) -> Optional[KernelCode]:
    for kc in kernel_code(ctx):
        if kc.pa <= pa < kc.pa + kc.size:
            return kc
    return None


# ------------------------------------------------------------------------------------------
# command streams
# ------------------------------------------------------------------------------------------
class ChannelCommands:
    def __init__(self, ib: InstanceBlock, aspace: Optional[AddressSpace]):
        self.ib, self.aspace = ib, aspace
        self.gp_entries: List[pushbuf.GpEntry] = []
        self.segments: List[dict] = []
        self.bindings: Dict[int, int] = {}
        self.error: Optional[str] = None

    @property
    def events(self):
        for s in self.segments:
            yield from s["events"]


def _ring_state(index: int, get: Optional[int], put: Optional[int], n: int) -> str:
    if get is None or put is None or n == 0:
        return "unknown"
    get, put = get % n, put % n
    if get == put:
        return "consumed"
    if get < put:
        return "pending" if get <= index < put else "consumed"
    return "pending" if (index >= get or index < put) else "consumed"


def channel_commands(ctx) -> List[ChannelCommands]:
    def build():
        out = []
        for ib in instance_blocks(ctx):
            cc = ChannelCommands(ib, address_space_of(ctx, ib))
            out.append(cc)
            if cc.aspace is None:
                cc.error = "no usable address space"
                continue
            n = ib.gp_entries
            if not n or n > (1 << 20):
                cc.error = "implausible GPFIFO size %d" % n
                continue
            if cc.aspace.translate(ib.gp_base_va) is None:
                cc.error = "GPFIFO VA 0x%x does not translate" % ib.gp_base_va
                continue
            raw = cc.aspace.layer.read(ib.gp_base_va, n * 8, pad=True)
            entries = [e for e in pushbuf.decode_gpfifo(raw) if e.raw != (0, 0)]
            cc.gp_entries = entries
            interp = pushbuf.CommandInterpreter(ctx.classdb)
            for e in entries:
                seg = {"entry": e, "state": _ring_state(e.index, ib.gp_get(), ib.gp_put(), n), "va": e.va,
                       "length": e.nbytes, "methods": [], "events": [], "readable": False, "pa": None}
                cc.segments.append(seg)
                if e.is_control or not e.nbytes:
                    continue
                t = cc.aspace.translate(e.va)
                if t is None:
                    continue
                seg["pa"] = t[1] if t[0].aperture == VID else None
                data = cc.aspace.layer.read(e.va, min(e.nbytes, 4 << 20), pad=True)
                seg["readable"] = True
                for m in pushbuf.decode_methods(data, e.va):
                    seg["methods"].append(m)
                    seg["events"].extend(interp.feed(m))
                seg["events"].extend(interp.finish())
            cc.bindings = dict(interp.bind)
        return out

    return ctx.cached("channel_commands", build)


class Launch:
    def __init__(self, channel: ChannelCommands, event, qmd, qmd_raw: Optional[bytes]):
        self.channel, self.event, self.qmd, self.qmd_raw = channel, event, qmd, qmd_raw
        self.program_va: Optional[int] = None
        self.program_pa: Optional[int] = None
        self.program_mapping = None
        self.kernel: Optional[KernelCode] = None


def launches(ctx) -> List[Launch]:
    def build():
        out = []
        for cc in channel_commands(ctx):
            for ev in cc.events:
                if ev.kind != "launch":
                    continue
                va = ev.details["qmd_va"]
                raw = q = None
                if cc.aspace and cc.aspace.translate(va):
                    raw = cc.aspace.layer.read(va, qmd_fmt.MAX_QMD_SIZE, pad=True)
                    q = qmd_fmt.decode(raw)  # version read from the descriptor itself
                ln = Launch(cc, ev, q, raw)
                if q is not None:
                    ln.program_va = q.resolve_program(ev.details.get("program_region"))
                if ln.program_va is not None and cc.aspace:
                    t = cc.aspace.translate(ln.program_va)
                    if t:
                        ln.program_mapping, ln.program_pa = t
                        if t[0].aperture == VID:
                            ln.kernel = code_at(ctx, t[1])
                out.append(ln)
        return out

    return ctx.cached("launches", build)


def sass_regions(ctx, layer: Optional[DataLayer] = None) -> List[dict]:
    """Raw SASS functions (located by their EXIT/BRA-self epilogue) in a physical layer."""
    layer = layer or ctx.primary

    def build():
        out = []
        for off, _ in scan(layer, RegexScanner(sass.EPILOGUE_RE, max_length=32, alignment=16)):
            start_win = max(layer.minimum_address, off - 64 * 1024)
            data = layer.read(start_win, off - start_win + 4096, pad=True)
            s, e = sass.code_extent(data, off - start_win)
            region = data[s:e]
            out.append({"layer": layer.name, "start": start_win + s, "end": start_win + e, "epilogue": off,
                        "score": sass.code_score(region)})
        return out

    return ctx.cached("sass_regions:" + layer.name, build)
