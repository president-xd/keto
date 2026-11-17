"""CUDA code in memory: cubins, fat binaries, PTX, and where kernels are loaded."""

from __future__ import annotations

import hashlib
import json

from keto.formats.cubin import DEVICE_IMPORTS_OF_INTEREST, demangle
from keto.formats.elf import STB_NAMES
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, TreeGrid, na
from keto.gpu import discovery


def _cubin_filter(ctx, offset):
    for fc in discovery.cubins(ctx):
        if offset is None or fc.offset == offset:
            yield fc


class CubinScan(Plugin):
    NAME = "nvidia.cubinscan"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Finds CUDA binaries (cubin ELF files, e_machine 190) anywhere in the image, including freed "
                   "staging copies and ones inside fat binaries, and summarises each.")
    METHOD = ("Scans for the ELF64 magic, keeps EM_CUDA images, sizes them from section/program headers, and "
              "parses SM architecture (e_flags; ABI v7 bits 7:0, ABI v8 bits 15:8), toolkit version "
              "(.note.nv.cuinfo) and kernels (.text.<name> STT_FUNC symbols). Fatbin ELF entries are "
              "decompressed first (LZ4, zstd or deflate, per the entry flags).")
    ANALOG = "windows.modscan"

    def run(self):
        def rows():
            for fc in discovery.cubins(self.ctx):
                c = fc.cubin
                if c is None:
                    yield 0, (fc.layer, Address(fc.offset), fc.size, fc.source, na(""), na(""), na(""), 0,
                              "parse error: %s" % fc.error)
                    continue
                yield 0, (fc.layer, Address(fc.offset), fc.size, fc.source, c.arch,
                          "sm_%d" % c.virtual_sm if c.virtual_sm else na("unknown"), c.toolkit_version or na("unknown"),
                          len(c.kernels), ", ".join(k.name for k in c.kernels[:6]) + (" ..." if len(c.kernels) > 6 else ""))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Size", int), ("Source", str), ("Arch", str),
                         ("PTX target", str), ("Toolkit", str), ("Kernels", int), ("Names", str)], rows())


class FatbinScan(Plugin):
    NAME = "nvidia.fatbinscan"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Finds CUDA fat binaries (the containers nvcc embeds in host programs) and their PTX/ELF "
                   "entries, plus __nv_fatbinwrap descriptors (host-side pointers to fatbins).")
    METHOD = ("Scans for the fatbin header magic 0xBA55ED50, walks the 64-byte entry headers (kind, arch, size, "
              "flags), LZ4-decompresses entries flagged 0x2000, and scans for wrapper magic 0x466243B1.")
    ANALOG = "windows.unloadedmodules (container view of loadable code)"

    def run(self):
        def rows():
            for fb in discovery.fatbins(self.ctx):
                f = fb["fatbin"]
                yield 0, (fb["layer"], Address(fb["offset"]), "fatbin", f.total_size, na(""), na(""), "%d entries" % len(f.entries))
                for e in f.entries:
                    status = e.error or ("ok, %d bytes" % len(e.data or b""))
                    yield 1, (fb["layer"], Address(e.offset), e.kind_name, e.size, "sm_%d" % e.arch,
                              e.compression or "none", status)
            for w in discovery.fatbin_wrappers(self.ctx):
                yield 0, (w["layer"], Address(w["offset"]), "__nv_fatbinwrap", 24, na(""), na(""),
                          "data=0x%x version=%d" % (w["data_ptr"], w["version"]))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Kind", str), ("Size", int), ("Arch", str),
                         ("Compression", str), ("Status", str)], rows())


class PtxScan(Plugin):
    NAME = "nvidia.ptxscan"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Finds PTX source modules (NVIDIA's virtual ISA, JIT-compiled by the driver) and lists their "
                   "target, entry points, external functions and generator.")
    METHOD = ("Regex-scans for '.version X.Y', carves the surrounding printable text, and parses .target, "
              ".address_size, .entry/.func/.extern/.global directives; PTX entries of fat binaries are included.")
    ANALOG = "windows.filescan (recover code 'files' from memory)"

    def run(self):
        def rows():
            for p in discovery.ptx_modules(self.ctx):
                m = p["module"]
                yield 0, (p["layer"], Address(p["offset"]), p["size"], p["source"], m.version or na(""),
                          m.target or na(""), ", ".join(m.entries) or "-", ", ".join(m.externs) or "-",
                          "; ".join(m.generator[:2]) or "-")
        return TreeGrid([("Layer", str), ("Offset", Address), ("Size", int), ("Source", str), ("PTX", str),
                         ("Target", str), ("Entries", str), ("Externs", str), ("Generator", str)], rows())


class Kernels(Plugin):
    NAME = "nvidia.kernels"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Lists GPU kernels whose machine code is present in VRAM, where it is mapped in each address "
                   "space, with which permissions, and whether it was launched.")
    METHOD = ("Takes every kernel .text from cubins found in the image, the host image and --reference files, "
              "searches VRAM for its first 48 bytes, confirms by full byte comparison (match ratio tolerates "
              "relocation patches), then reverse-maps the physical address through all page tables.")
    ANALOG = "windows.dlllist / linux.library_list"

    def run(self):
        launched = {}
        for ln in discovery.launches(self.ctx):
            if ln.kernel:
                launched[ln.kernel.pa] = launched.get(ln.kernel.pa, 0) + 1

        def rows():
            for kc in discovery.kernel_code(self.ctx):
                maps = discovery.reverse_lookup_all(self.ctx, kc.pa)
                where = "; ".join("%s:0x%x %s" % (a.name, va, m.flags()) for a, va, m in maps) or "unmapped"
                yield 0, (Address(kc.pa), kc.size, kc.kernel.demangled, kc.kind, round(kc.match_ratio, 3),
                          "%s@0x%x" % (kc.found.layer, kc.found.offset), where, launched.get(kc.pa, 0))
        return TreeGrid([("PA", Address), ("Size", int), ("Kernel", str), ("Kind", str), ("Match", float),
                         ("FromCubin", str), ("MappedAt", str), ("Launches", int)], rows())


class CubinInfo(Plugin):
    NAME = "nvidia.cubininfo"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Shows build metadata of each cubin and each kernel: SM/PTX architecture, toolkit and ptxas "
                   "versions and command line, registers, parameters, stack/frame sizes, exit offsets.")
    METHOD = ("Parses .note.nv.tkinfo / .note.nv.cuinfo notes and the EIATTR records of .nv.info and "
              ".nv.info.<kernel> (format byte, attribute id, value/payload); register count also from "
              ".text section sh_info[31:24].")
    ANALOG = "windows.verinfo"
    REQUIREMENTS = [Requirement("offset", "address", None, "only the cubin at this offset")]

    def run(self):
        def rows():
            for fc in _cubin_filter(self.ctx, self.opts["offset"]):
                c = fc.cubin
                if c is None:
                    continue
                elf = c.elf
                yield 0, ("%s@0x%x" % (fc.layer, fc.offset), "cubin",
                          "%s ABI v%d OSABI 0x%x e_flags 0x%x" % (c.arch, elf.abiversion, elf.osabi, elf.e_flags),
                          "toolkit %s; %s" % (c.toolkit_version or "?", " | ".join(c.tool_strings[:4])))
                for k in c.kernels:
                    attrs = {kk: vv for kk, vv in k.attributes.items() if kk not in ("exit_offsets",)}
                    yield 1, (k.name, "kernel", "regs=%d size=%d sha256=%s" % (k.regcount, k.size, k.sha256[:16]),
                              "params=%s exits=%s attrs=%s" % (json.dumps(k.params), k.attributes.get("exit_offsets"),
                                                               json.dumps(attrs, default=str)))
        return TreeGrid([("Object", str), ("Kind", str), ("Build", str), ("Details", str)], rows())


class Symbols(Plugin):
    NAME = "nvidia.symbols"
    CATEGORY = "nvidia.code"
    DESCRIPTION = "Lists the ELF symbols of each cubin (kernels, device functions, globals, constants, imports)."
    METHOD = "Reads .symtab with its string table; names are demangled (Itanium, function part) for readability."
    ANALOG = "windows.pe_symbols"
    REQUIREMENTS = [Requirement("offset", "address", None, "only the cubin at this offset")]

    def run(self):
        def rows():
            for fc in _cubin_filter(self.ctx, self.opts["offset"]):
                if fc.cubin is None:
                    continue
                elf = fc.cubin.elf
                secs = {s.index: s.name for s in elf.sections}
                for s in elf.symbols():
                    if not s.name:
                        continue
                    yield 0, ("%s@0x%x" % (fc.layer, fc.offset), s.name, demangle(s.name), s.type_name,
                              STB_NAMES.get(s.bind, str(s.bind)), secs.get(s.shndx, "UND" if s.shndx == 0 else
                                                                            str(s.shndx)), s.value, s.size)
        return TreeGrid([("Cubin", str), ("Symbol", str), ("Demangled", str), ("Type", str), ("Bind", str),
                         ("Section", str), ("Value", int), ("Size", int)], rows())


class Imports(Plugin):
    NAME = "nvidia.imports"
    CATEGORY = "nvidia.code"
    DESCRIPTION = ("Lists external functions GPU code depends on: undefined cubin symbols and PTX .extern "
                   "functions (device printf, device malloc, dynamic-parallelism launches...).")
    METHOD = "Collects SHN_UNDEF global symbols from every cubin and .extern .func declarations from every PTX module."
    ANALOG = "windows.iat"

    def run(self):
        def rows():
            for fc in discovery.cubins(self.ctx):
                if fc.cubin:
                    for name in fc.cubin.imports:
                        yield 0, ("cubin", "%s@0x%x" % (fc.layer, fc.offset), name,
                                  DEVICE_IMPORTS_OF_INTEREST.get(name, "-"))
            for p in discovery.ptx_modules(self.ctx):
                for name in p["module"].externs:
                    yield 0, ("ptx", "%s@0x%x" % (p["layer"], p["offset"]), name,
                              DEVICE_IMPORTS_OF_INTEREST.get(name, "-"))
        return TreeGrid([("From", str), ("Object", str), ("Import", str), ("Meaning", str)], rows())


class CubinDump(Plugin):
    NAME = "nvidia.cubindump"
    CATEGORY = "nvidia.code"
    DESCRIPTION = "Extracts cubins, decompressed fatbin entries and PTX modules to files (for cuobjdump/nvdisasm)."
    METHOD = ("Writes each carved object exactly as found (fatbin entries decompressed) and records size and "
              "SHA-256; file names encode layer, offset and kind.")
    ANALOG = "windows.pedump / linux.elfs --dump"
    REQUIREMENTS = [Requirement("offset", "address", None, "only the object at this offset")]

    def run(self):
        def write(name, data):
            path = self.ctx.output_path(name)
            with open(path, "wb") as fh:
                fh.write(data)
            return path

        def rows():
            off = self.opts["offset"]
            for fc in discovery.cubins(self.ctx):
                if off is not None and fc.offset != off or fc.source == "reference":
                    continue
                layer = self.ctx.layers.get(fc.layer)
                data = None
                if fc.source.startswith("fatbin"):
                    for fb in discovery.fatbins(self.ctx):
                        for e in fb["fatbin"].entries:
                            if e.offset == fc.offset:
                                data = e.data
                elif layer is not None:
                    data = layer.read(fc.offset, fc.size, pad=True)
                if not data:
                    continue
                p = write("cubin_%s_%x.cubin" % (fc.layer, fc.offset), data)
                yield 0, ("cubin", Address(fc.offset), len(data), hashlib.sha256(data).hexdigest(), p)
            for pm in discovery.ptx_modules(self.ctx):
                if off is not None and pm["offset"] != off:
                    continue
                data = pm["module"].text.encode()
                p = write("ptx_%s_%x.ptx" % (pm["layer"], pm["offset"]), data)
                yield 0, ("ptx", Address(pm["offset"]), len(data), hashlib.sha256(data).hexdigest(), p)
        return TreeGrid([("Kind", str), ("Offset", Address), ("Size", int), ("SHA256", str), ("File", str)], rows())
