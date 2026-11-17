"""One-pass sweep for GPU artefacts in any memory: VRAM, a host RAM image, or a
single process's address space.

Malware that hides its payload on the GPU still has to stage it through host
memory: the launching process holds the fat binary / cubin / PTX it loads, the
pushbuffers and launch descriptors (QMDs) its driver builds, and often a
decrypted copy of the kernel. ``sweep`` finds all of these with the same
parsers the VRAM plugins use, so one routine serves VRAM images, process
dumps and live process memory.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Iterator, Optional

from keto.formats import cubin as cubin_fmt
from keto.formats import fatbin as fatbin_fmt
from keto.formats import gpucode
from keto.formats import ptx as ptx_fmt
from keto.formats.elf import elf_extent
from keto.framework.layers import DataLayer
from keto.framework.scanners import AnchoredScanner, BytesScanner, RegexScanner, scan, scan_aligned_u32
from keto.gpu import pushbuf, qmd as qmd_fmt, sass

KINDS = ("fatbin", "fatbinwrap", "cubin", "ptx", "pushbuffer", "qmd", "sass", "opencl", "spirv", "dxbc")


class Artefact:
    __slots__ = ("kind", "layer", "offset", "size", "summary", "detail")

    def __init__(self, kind, layer, offset, size, summary, detail=None):
        self.kind, self.layer, self.offset, self.size = kind, layer, offset, size
        self.summary, self.detail = summary, detail or {}

    def __repr__(self):
        return "<Artefact %s @0x%x %s>" % (self.kind, self.offset, self.summary)


def _read(layer: DataLayer, off: int, n: int) -> bytes:
    return layer.read(off, max(0, min(n, layer.maximum_address + 1 - off)), pad=True)


def sweep(layer: DataLayer, classdb, kinds=KINDS, qmd_version: Optional[str] = "v03_00",
          min_methods: int = 3) -> Iterator[Artefact]:
    """Yield every GPU artefact found in ``layer``."""
    kinds = set(kinds)
    containers = []  # (start, end) of fatbins/cubins already reported; raw SASS inside them is not re-reported
    code_chunks = {}  # 32-byte instruction pairs of every cubin kernel seen -> (kernel name, sha256)
    if "fatbin" in kinds:
        for off, _ in scan(layer, BytesScanner(fatbin_fmt.FATBIN_MAGIC_BYTES)):
            size = struct.unpack_from("<Q", _read(layer, off, 16), 8)[0]
            if not 0 < size < (256 << 20):
                continue
            fb = fatbin_fmt.parse_fatbin(_read(layer, off, 16 + size), off)
            if fb:
                ents = ["%s sm_%d%s%s" % (e.kind_name, e.arch, " " + e.compression if e.compressed else "",
                                          " (undecodable)" if e.data is None else "") for e in fb.entries]
                names, hashes = [], []
                for e in fb.entries:
                    if e.kind == fatbin_fmt.KIND_ELF and e.data:
                        try:
                            c = cubin_fmt.parse_cubin(e.data)
                            names += c.kernel_names()
                            hashes += [k.sha256 for k in c.kernels]
                        except Exception:
                            pass
                    elif e.kind == fatbin_fmt.KIND_PTX and e.data:
                        names += ptx_fmt.parse(e.data.split(b"\x00", 1)[0]).entries
                containers.append((off, off + fb.total_size))
                yield Artefact("fatbin", layer.name, off, fb.total_size, "; ".join(ents),
                               {"kernels": sorted(set(names)), "hashes": hashes})
    if "fatbinwrap" in kinds:
        for off, _ in scan(layer, BytesScanner(fatbin_fmt.WRAPPER_MAGIC_BYTES)):
            w = fatbin_fmt.parse_wrapper(_read(layer, off, 24))
            if w:
                yield Artefact("fatbinwrap", layer.name, off, 24, "__nv_fatbinwrap -> 0x%x" % w["data_ptr"], w)
    if "cubin" in kinds:
        for off, _ in scan(layer, BytesScanner(b"\x7fELF\x02\x01")):
            head = _read(layer, off, 64)
            if len(head) < 20 or struct.unpack_from("<H", head, 18)[0] != cubin_fmt.EM_CUDA:
                continue
            window = _read(layer, off, 16 << 20)
            size = elf_extent(window) or 64
            containers.append((off, off + size))
            try:
                c = cubin_fmt.parse_cubin(window[:size])
                for k in c.kernels:
                    for i in range(0, len(k.text) - 31, 16):
                        chunk = k.text[i:i + 32]
                        if chunk.count(0) < 24 and chunk[:16] != sass.NOP_INSN:
                            code_chunks.setdefault(chunk, (k.name, k.sha256))
                yield Artefact("cubin", layer.name, off, size, "%s, %d kernel(s)" % (c.arch, len(c.kernels)),
                               {"kernels": c.kernel_names(), "toolkit": c.toolkit_version,
                                "hashes": [k.sha256 for k in c.kernels],
                                "kernel_hashes": {k.sha256: k.name for k in c.kernels}})
            except Exception as exc:
                yield Artefact("cubin", layer.name, off, size, "unparseable: %s" % exc)
    if "ptx" in kinds:
        last_end = -1
        for off, _ in scan(layer, RegexScanner(ptx_fmt.VERSION_RE, max_length=32)):
            if off < last_end:
                continue
            start_win = max(layer.minimum_address, off - 4096)
            data = _read(layer, start_win, 4 << 20)
            span = ptx_fmt.carve(data, off - start_win)
            if not span:
                continue
            mod = ptx_fmt.parse(data[span[0]:span[1]])
            if mod.target is None and not mod.entries:
                continue
            last_end = start_win + span[1]
            text = data[span[0]:span[1]]
            digest = "ptx:" + hashlib.sha256(text.strip()).hexdigest()
            dec = gpucode.ptx_decryptor_pattern(text)
            yield Artefact("ptx", layer.name, start_win + span[0], span[1] - span[0],
                           "PTX %s %s%s" % (mod.version, mod.target, ", XOR+remainder (decryptor shape)" if dec else ""),
                           {"entries": mod.entries, "externs": mod.externs, "hashes": [digest],
                            "kernel_hashes": {digest: "ptx:" + ",".join(mod.entries)}, "decryptor": dec})
    if "opencl" in kinds:
        last_end = -1
        sc = AnchoredScanner([b"__kernel", b"kernel void"], gpucode.KERNEL_RE, before=0, after=400)
        for off, _ in sorted(scan(layer, sc), key=lambda h: h[0]):
            if off < last_end:
                continue
            start_win = max(layer.minimum_address, off - 65536)
            data = _read(layer, start_win, off - start_win + (1 << 20))
            s, e = gpucode.carve_text(data, off - start_win)
            src = gpucode.parse_opencl(data[s:e])
            last_end = start_win + e
            if src is None:
                continue
            digest = "ocl:" + hashlib.sha256(src.text.strip()).hexdigest()
            yield Artefact("opencl", layer.name, start_win + s, e - s,
                           "OpenCL C source, %d kernel(s)%s" % (len(src.kernels),
                                                                ", XOR with modulo-indexed key (decryptor shape)"
                                                                if src.decryptor_pattern else ""),
                           {"entries": src.kernels, "decryptor": src.decryptor_pattern, "hashes": [digest],
                            "kernel_hashes": {digest: "opencl:" + ",".join(src.kernels)},
                            "preview": src.text[:160].decode("ascii", "replace")})
    if "spirv" in kinds:
        for off, _ in scan(layer, BytesScanner(gpucode.SPIRV_MAGIC_BYTES, alignment=4)):
            data = _read(layer, off, gpucode.MAX_SPIRV)
            mod = gpucode.parse_spirv(data)
            if mod is None:
                continue
            containers.append((off, off + mod.size))
            digest = "spirv:" + hashlib.sha256(data[:mod.size]).hexdigest()
            names = [n for _, n in mod.entries]
            yield Artefact("spirv", layer.name, off, mod.size,
                           "SPIR-V %d.%d %s%s%s" % (mod.version + (", ".join("%s %s" % e for e in mod.entries)
                                                                   or "no entry points",
                                                                   " (OpenCL)" if mod.is_opencl else "",
                                                                   ", XOR+modulo (decryptor shape)"
                                                                   if mod.decryptor_pattern else "")),
                           {"entries": names, "opencl": mod.is_opencl, "decryptor": mod.decryptor_pattern,
                            "source_language": mod.source_language, "hashes": [digest],
                            "kernel_hashes": {digest: "spirv:" + ",".join(names)}})
    if "dxbc" in kinds:
        for off, _ in scan(layer, BytesScanner(gpucode.DXBC_MAGIC)):
            data = _read(layer, off, 1 << 20)
            c = gpucode.parse_dxbc(data)
            if c is None:
                continue
            body = _read(layer, off, c.size)
            digest = "dxbc:" + hashlib.sha256(body).hexdigest()
            yield Artefact("dxbc", layer.name, off, c.size,
                           "Direct3D %s shader, SM %s%s (%s)" % (c.program_type or "?", c.shader_model or "?",
                                                                 " DXIL" if c.dxil else "",
                                                                 ", ".join(p[0] for p in c.parts)),
                           {"program_type": c.program_type, "dxil": c.dxil, "hashes": [digest],
                            "kernel_hashes": {digest: "dxbc:%s" % c.program_type}})
    if "pushbuffer" in kinds and classdb is not None:
        sc = AnchoredScanner([b"\x01\x20", b"\x01\x60", b"\x01\xa0"], pushbuf.SET_OBJECT_RE, before=2, after=8)
        sc.alignment = 4
        last_end = -1
        for off, m in sorted(scan(layer, sc), key=lambda h: h[0]):
            cls = int.from_bytes(m.group(1), "little")
            if cls not in classdb.classes or off < last_end:
                continue
            data = _read(layer, off, 0x4000)
            methods, events, _ = pushbuf.interpret(data, off, classdb)
            if len(methods) < min_methods:
                continue
            last_end = methods[-1].offset + 4
            kinds_seen = {}
            for ev in events:
                kinds_seen[ev.kind] = kinds_seen.get(ev.kind, 0) + 1
            yield Artefact("pushbuffer", layer.name, off, last_end - off,
                           "%s, %d methods, %s" % (classdb.class_name(cls), len(methods),
                                                   ", ".join("%d %s" % (n, k) for k, n in sorted(kinds_seen.items()))),
                           {"events": events})
    if "qmd" in kinds:
        seen_q = set()
        for woff, mask, values in qmd_fmt.scan_signatures():
            for off, _ in scan_aligned_u32(layer, woff, qmd_fmt.QMD_SIZE, lambda v: (v & mask) in values):
                if off in seen_q:
                    continue
                q = qmd_fmt.decode(_read(layer, off, qmd_fmt.MAX_QMD_SIZE))
                if q is not None and q.plausible():
                    seen_q.add(off)
                    prog = "prog=0x%x" % q.program_address if q.program_address is not None else \
                        "prog_offset=0x%x" % (q.program_offset or 0)
                    yield Artefact("qmd", layer.name, off, q.layout["size"],
                                   "%s launch %s grid=%dx%dx%d block=%dx%dx%d" % ((q.version.upper(), prog) + q.grid
                                                                                 + q.block), {"qmd": q})
    if "sass" in kinds:
        for off, _ in scan(layer, RegexScanner(sass.EPILOGUE_RE, max_length=32, alignment=16)):
            if any(s <= off < e for s, e in containers):
                continue  # .text of a cubin already reported above
            start_win = max(layer.minimum_address, off - 65536)
            data = _read(layer, start_win, off - start_win + 4096)
            s, e = sass.code_extent(data, off - start_win)
            body = data[s:e]
            votes, total = {}, 0
            for i in range(0, len(body) - 31, 16):
                chunk = body[i:i + 32]
                if chunk.count(0) >= 24 or chunk[:16] == sass.NOP_INSN:
                    continue
                total += 1
                hit = code_chunks.get(chunk)
                if hit:
                    votes[hit] = votes.get(hit, 0) + 1
            skel = sass.skeleton_hash(body)
            detail = {"hashes": [skel], "kernel_hashes": {skel: "sass@0x%x" % (start_win + s)}}
            summary = "SASS function, %d instructions" % ((e - s) // 16)
            if votes and total:
                (kname, ksha), n = max(votes.items(), key=lambda kv: kv[1])
                if n / total >= 0.6:  # tolerate relocation patches in loaded copies
                    detail = {"kernels": [kname], "hashes": [ksha], "match": round(n / total, 3),
                              "kernel_hashes": {ksha: kname}}
                    summary = "loaded copy of kernel %s (%.0f%% instruction match)" % (kname, 100.0 * n / total)
            yield Artefact("sass", layer.name, start_win + s, e - s, summary, detail)
