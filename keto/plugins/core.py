"""Framework / vendor-independent plugins (Volatility's top-level plugins)."""

from __future__ import annotations

import json
import os
import platform
import re

from keto import __version__
from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.plugin import PLUGINS, Plugin, Requirement, TimeLinerInterface
from keto.framework.renderers import RENDERERS
from keto.framework.scanners import AnchoredScanner, RegexScanner, scan
from keto.framework.treegrid import Address, Bytes, Disassembly, TreeGrid, na
from keto.framework.util import hexdump

# (kind, anchor literal, regex starting at the anchor)
BANNER_PATTERNS = [
    ("NVIDIA kernel module", b"NVRM version: ", rb"NVRM version: NVIDIA [\x20-\x7e]{5,120}"),
    ("NVIDIA kernel module", b"NVIDIA UNIX ",
     rb"NVIDIA UNIX (?:x86_64|aarch64|Open)[\x20-\x7e]{0,20}Kernel Module[ ]+\d+\.\d+(?:\.\d+)?"),
    ("nvidia-smi", b"NVIDIA-SMI ", rb"NVIDIA-SMI \d+\.\d+(?:\.\d+)?"),
    ("driver version", b"Driver Version: ", rb"Driver Version: \d+\.\d+(?:\.\d+)?"),
    ("CUDA version", b"CUDA Version", rb"CUDA Version:? \d+\.\d+"),
    ("CUDA toolkit", b"Cuda compilation tools", rb"Cuda compilation tools, release \d+\.\d+, V[\d.]+"),
    ("GPU product", b"NVIDIA ", rb"NVIDIA (?:GeForce |Quadro |Tesla |RTX |TITAN |DGX )?(?:RTX |GTX |MX )?[A-Z]?\d{2,4}"
                               rb"[\w ]{0,24}(?:GPU|Laptop GPU|Ti|SUPER|PCIe|SXM\w*)"),
    ("VBIOS version", b"Version ", rb"Version \d{2}\.\d{2}\.[0-9A-F]{2}\.[0-9A-F]{2}\.[0-9A-F]{2}"),
    ("Linux kernel", b"Linux version ", rb"Linux version \d+\.\d+[\x20-\x7e]{0,200}"),
    ("Darwin kernel", b"Darwin Kernel Version ", rb"Darwin Kernel Version \d+\.\d+[\x20-\x7e]{0,120}"),
]


class Banners(Plugin):
    NAME = "banners"
    CATEGORY = "framework"
    DESCRIPTION = ("Finds NVIDIA driver, CUDA, VBIOS and GPU-product banners (and host kernel banners) to identify "
                   "the exact driver/hardware the image came from.")
    METHOD = "Regex-scans the primary layer (and --host-image) for known banner formats; de-duplicates by text."
    ANALOG = "banners"
    REQUIREMENTS = [Requirement("limit", int, 200, "maximum distinct banners")]

    def run(self):
        layers = [self.ctx.primary] + ([self.ctx.layers["sysmem"]] if "sysmem" in self.ctx.layers else [])
        seen = {}
        spans = []  # (layer, start, end, key): a banner inside a longer banner of the same kind is not repeated
        for layer in layers:
            for kind, anchor, pattern in BANNER_PATTERNS:
                for off, m in scan(layer, AnchoredScanner([anchor], re.compile(pattern), after=256)):
                    text = m.group().decode("ascii", "replace").strip()
                    spans.append((layer.name, off, off + len(m.group()), kind, text))
        spans.sort(key=lambda s: (s[0], s[1], -(s[2] - s[1])))
        covered = {}
        for lname, start, end, kind, text in spans:
            prev = covered.get((lname, kind))
            if prev is not None and prev[0] <= start and end <= prev[1]:
                continue  # e.g. "NVIDIA UNIX ... Kernel Module 590.74" inside the "NVRM version:" banner
            covered[(lname, kind)] = (start, end)
            key = (kind, text)
            if key not in seen:
                seen[key] = [lname, start, 0]
            seen[key][2] += 1
        rows = [(0, (layer, Address(off), kind, count, text)) for (kind, text), (layer, off, count) in
                sorted(seen.items(), key=lambda kv: (kv[1][0], kv[1][1]))][: self.opts["limit"]]
        return TreeGrid([("Layer", str), ("Offset", Address), ("Kind", str), ("Count", int), ("Banner", str)], rows)


class FrameworkInfo(Plugin):
    NAME = "frameworkinfo"
    CATEGORY = "framework"
    DESCRIPTION = "Lists the installed framework components: plugins per category, renderers, profiles, layers."
    METHOD = "Enumerates the plugin registry, renderer table and profile registry."
    ANALOG = "frameworkinfo"
    SOURCES = ("file",)

    def run(self):
        rows = [(0, ("framework", "Keto", __version__)), (0, ("python", platform.python_implementation(),
                                                                    platform.python_version()))]
        cats = {}
        for cls in PLUGINS.values():
            cats.setdefault(cls.CATEGORY, []).append(cls.NAME)
        for cat in sorted(cats):
            rows.append((0, ("plugins", cat, "%d" % len(cats[cat]))))
            for n in sorted(cats[cat]):
                rows.append((1, ("plugin", n, PLUGINS[n].ANALOG or "-")))
        for r in sorted(RENDERERS):
            rows.append((0, ("renderer", r, "-")))
        for p in sorted(self.ctx.registry.profiles.values(), key=lambda p: p.name):
            rows.append((0, ("profile", p.name, "%s / MMU %s" % (p.architecture, p.mmu_format))))
        for name, layer in sorted(self.ctx.layers.items()):
            rows.append((0, ("layer", name, layer.describe())))
        return TreeGrid([("Component", str), ("Name", str), ("Detail", str)], rows)


class ProfileInfo(Plugin):
    NAME = "profileinfo"
    CATEGORY = "framework"
    DESCRIPTION = ("Lists the available GPU architecture profiles (the symbol tables of this framework), what "
                   "hardware each covers, and validates them.")
    METHOD = ("Loads every profile JSON from the built-in symbols directory and --profile-dir, validates the "
              "schema, and prints architecture, chipsets, MMU format, structure layout, QMD version and provenance.")
    ANALOG = "isfinfo"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("provenance", bool, False, "include the provenance notes")]

    def run(self):
        reg = self.ctx.registry
        rows = []
        for p in sorted(reg.profiles.values(), key=lambda p: p.name):
            chips = ", ".join("%s(0x%x)" % (n, c) for c, n in sorted(p.chipsets.items()))
            rows.append((0, (p.name, p.architecture, p.mmu_format.upper(), p.layout.name, p.qmd or "-",
                             ", ".join(p.compute_capabilities), chips, "valid", os.path.basename(p.path))))
            if self.opts["provenance"]:
                for note in p.provenance:
                    rows.append((1, (p.name, "provenance", "-", "-", "-", "-", note, "-", "-")))
        for path, err in reg.errors.items():
            rows.append((0, (os.path.basename(path), "?", "?", "?", "?", "?", "?", "INVALID: " + err, path)))
        return TreeGrid([("Profile", str), ("Architecture", str), ("MMU", str), ("Layout", str), ("QMD", str),
                         ("ComputeCap", str), ("Chipsets", str), ("Status", str), ("File", str)], rows)


class ConfigWriter(Plugin):
    NAME = "configwriter"
    CATEGORY = "framework"
    DESCRIPTION = ("Saves what the automagic detected (profile and why, layers, VRAM size, address spaces) so "
                   "later runs and reports can reuse it.")
    METHOD = "Runs profile detection and address-space discovery, then writes config.json to the output directory."
    ANALOG = "configwriter"

    def run(self):
        from keto.gpu import discovery
        prof = self.ctx.profile
        try:
            spaces = [{"name": a.name, "pdb": a.pdb, "aperture": a.aperture, "format": a.fmt,
                       "sources": a.sources} for a in discovery.address_spaces(self.ctx)]
        except UnsupportedError as exc:
            spaces = [{"error": str(exc)}]
        cfg = {"image": self.ctx.image_path, "profile": prof.name, "profile_reason": self.ctx.profile_reason,
               "vram_size": self.ctx.vram_size, "layers": {n: l.describe() for n, l in self.ctx.layers.items()},
               "address_spaces": spaces, "device": self.ctx.metadata.get("device")}
        path = na("no -o given")
        if self.ctx.output_dir:
            path = self.ctx.output_path("config.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2, default=str)
        rows = [(0, (k, json.dumps(v, default=str)[:300])) for k, v in cfg.items()]
        rows.append((0, ("written_to", str(path))))
        return TreeGrid([("Key", str), ("Value", str)], rows)


def make_sparse(fh) -> None:
    """Mark an open file sparse on NTFS so the gaps layerwriter seeks over take no disk space (POSIX file systems
    leave holes on their own). Best effort: a file system without sparse support just stores the zeros."""
    if os.name != "nt":
        return
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        returned = wintypes.DWORD()
        ctypes.windll.kernel32.DeviceIoControl(wintypes.HANDLE(msvcrt.get_osfhandle(fh.fileno())), 0x000900C4,
                                               None, 0, None, 0, ctypes.byref(returned), None)  # FSCTL_SET_SPARSE
    except (OSError, AttributeError, ValueError):
        pass


class LayerWriter(Plugin):
    NAME = "layerwriter"
    CATEGORY = "framework"
    DESCRIPTION = ("Exports a layer to a flat file: the primary/physical layer (gaps read back as zeros; the file "
                   "is sparse, so gaps take no disk space) or any GPU address space (readable runs back to back, "
                   "plus a .map file).")
    METHOD = ("Reads the selected layer's readable runs in 4 MiB blocks; physical layers are written at their "
              "own offsets into a sparse file, virtual layers sequentially with an offset map.")
    ANALOG = "layerwriter"
    REQUIREMENTS = [Requirement("layer", str, None, "layer name (default: primary); see frameworkinfo"),
                    Requirement("list", bool, False, "only list layers")]

    def run(self):
        from keto.gpu import discovery
        try:
            discovery.address_spaces(self.ctx)
        except UnsupportedError:
            pass
        if self.opts["list"]:
            return TreeGrid([("Layer", str), ("Description", str)],
                            [(0, (n, l.describe())) for n, l in sorted(self.ctx.layers.items())])
        name = self.opts["layer"] or self.ctx.primary_name
        layer = self.ctx.layers.get(name)
        if layer is None:
            raise RequirementError("unknown layer %r; use --list" % name)
        virtual = layer.KIND == "gpu-va"
        path = self.ctx.output_path(name + (".vmem" if virtual else ".raw"))
        written = 0
        maplines = []
        with open(path, "wb") as fh:
            if not virtual:
                make_sparse(fh)
            for start, length in layer.ranges():
                if not virtual:
                    fh.seek(start)
                else:
                    maplines.append("0x%x 0x%x 0x%x" % (start, length, fh.tell()))
                pos = start
                while pos < start + length:
                    n = min(4 << 20, start + length - pos)
                    fh.write(layer.read(pos, n, pad=True))
                    pos += n
                    written += n
        if virtual:
            with open(path + ".map", "w") as fh:
                fh.write("# va length file_offset\n" + "\n".join(maplines) + "\n")
        return TreeGrid([("Layer", str), ("File", str), ("Bytes", int), ("Runs", int)],
                        [(0, (name, path, written, len(layer.ranges())))])


def resolve_layer(ctx, name):
    """The layer called ``name`` (default: the primary layer). GPU address spaces (``as_<pdb>``) are discovered
    on demand; an unknown name raises RequirementError listing the available layers."""
    name = name or ctx.primary_name
    if name and name.startswith("as_") and name not in ctx.layers:
        from keto.gpu import discovery
        try:
            discovery.address_spaces(ctx)
        except UnsupportedError:
            pass
    layer = ctx.layers.get(name) if name else None
    if layer is None:
        raise RequirementError("unknown layer %r (available: %s; GPU address spaces are as_<pdb>, see "
                               "nvidia.addrspaces)" % (name, ", ".join(sorted(ctx.layers)) or "none"))
    return layer


def compile_regex(pattern: str):
    try:
        return re.compile(pattern.encode("utf-8", "surrogateescape"), re.DOTALL)
    except re.error as exc:
        raise RequirementError("invalid --pattern %r: %s" % (pattern, exc))


class RegexScan(Plugin):
    NAME = "regexscan"
    CATEGORY = "framework"
    DESCRIPTION = ("Searches a layer (default: the primary physical layer; any GPU address space as as_<pdb>) for a "
                   "regular expression.")
    METHOD = "Runs a bytes regex chunk by chunk with overlap so matches across chunk boundaries are kept."
    ANALOG = "regexscan"
    REQUIREMENTS = [Requirement("pattern", str, None, "regular expression"),
                    Requirement("layer", str, None, "layer name"), Requirement("max_length", int, 256, "max match length")]

    def run(self):
        if not self.opts["pattern"]:
            raise RequirementError("--pattern is required")
        if self.opts["max_length"] < 1:
            raise RequirementError("--max-length must be at least 1")
        layer = resolve_layer(self.ctx, self.opts["layer"])
        rx = compile_regex(self.opts["pattern"])
        rows = ((0, (layer.name, Address(off), Bytes(m.group()[:self.opts["max_length"]])))
                for off, m in scan(layer, RegexScanner(rx, max_length=self.opts["max_length"])))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Match", Bytes)], rows)


BUILTIN_RULES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "gpu_threats.yar")


def compile_yara(rule_text, rule_file, builtin=False):
    try:
        import yara  # optional dependency
    except ImportError:
        raise UnsupportedError("yara-python is not installed (pip install yara-python); for plain patterns use "
                               "regexscan / nvidia.varegexscan")
    if builtin and not (rule_file or rule_text):
        rule_file = BUILTIN_RULES
    if not rule_file and not rule_text:
        raise RequirementError("--yara-rules, --yara-file or --builtin is required")
    if rule_file and not os.path.isfile(rule_file):
        raise RequirementError("YARA rules file not found: %s" % rule_file)
    if not rule_file and "rule " not in rule_text:
        rule_text = 'rule r1 { strings: $a = "%s" condition: $a }' % rule_text.replace('"', '\\"')
    try:
        return yara.compile(filepath=rule_file) if rule_file else yara.compile(source=rule_text)
    except yara.Error as exc:  # SyntaxError and friends derive from yara.Error
        raise RequirementError("YARA rules do not compile: %s" % exc)


def yara_hits(rules, layer, chunk=16 << 20, overlap=4096):
    for off, data, payload in layer.iter_chunks(chunk, overlap):
        for match in rules.match(data=data):
            for s in match.strings:
                if hasattr(s, "instances"):  # yara-python >= 4.3
                    for inst in s.instances:
                        if inst.offset < payload:
                            yield off + inst.offset, match.rule, s.identifier, bytes(inst.matched_data)
                else:
                    o, ident, d = s
                    if o < payload:
                        yield off + o, match.rule, ident, d


class YaraScan(Plugin):
    NAME = "yarascan"
    CATEGORY = "framework"
    DESCRIPTION = "Scans a layer (default: primary physical layer) with YARA rules."
    METHOD = "Compiles rules with yara-python and scans the layer in overlapping 16 MiB chunks."
    ANALOG = "yarascan"
    REQUIREMENTS = [Requirement("yara_rules", str, None, "inline rule text or a bare string"),
                    Requirement("yara_file", str, None, "rules file"), Requirement("layer", str, None, "layer name"),
                    Requirement("builtin", bool, False, "use the bundled GPU threat rules (keto/rules)")]

    def run(self):
        rules = compile_yara(self.opts["yara_rules"], self.opts["yara_file"], self.opts["builtin"])
        layer = resolve_layer(self.ctx, self.opts["layer"])
        rows = ((0, (layer.name, Address(o), r, i, Bytes(d[:64]))) for o, r, i, d in yara_hits(rules, layer))
        return TreeGrid([("Layer", str), ("Offset", Address), ("Rule", str), ("String", str), ("Data", Bytes)], rows)


MAX_HEXDUMP = 16 << 20


class HexDump(Plugin):
    NAME = "hexdump"
    CATEGORY = "framework"
    DESCRIPTION = "Hex-dumps bytes from any layer (physical VRAM, host memory, or a GPU virtual address space)."
    METHOD = ("Reads through the chosen layer (translating GPU VAs via the page tables) and formats 16 bytes per "
              "line; bytes that are not backed by the layer (unmapped VAs, gaps, beyond the image) are reported in "
              "the Unbacked column and shown as zeros.")
    ANALOG = "volshell db/dq"
    REQUIREMENTS = [Requirement("address", "address", None, "start address"),
                    Requirement("length", "size", 256, "bytes (at most 16M; use layerwriter or memmap --dump "
                                                       "for more)"),
                    Requirement("layer", str, None, "layer name (as_<pdb> for a GPU address space)")]

    def run(self):
        if self.opts["address"] is None:
            raise RequirementError("--address is required")
        length = self.opts["length"]
        if not 0 < length <= MAX_HEXDUMP:
            raise RequirementError("--length must be between 1 and %d bytes" % MAX_HEXDUMP)
        layer = resolve_layer(self.ctx, self.opts["layer"])
        addr = self.opts["address"]
        data = layer.read(addr, length, pad=True)
        backed = 0
        for start, rlen in layer.ranges():
            lo, hi = max(addr, start), min(addr + length, start + rlen)
            if hi > lo:
                backed += hi - lo
        unbacked = length - backed
        note = ("all %d byte(s) backed" % length if not unbacked else
                "%d of %d byte(s) NOT backed by %s (shown as zeros)" % (unbacked, length, layer.name))
        return TreeGrid([("Layer", str), ("Address", Address), ("Unbacked", str), ("Dump", Disassembly)],
                        [(0, (layer.name, Address(addr), note, Disassembly(hexdump(data, addr))))])


class Verify(Plugin):
    NAME = "verify"
    CATEGORY = "framework"
    DESCRIPTION = ("Verifies the integrity of a .keto evidence container (VRAM, host RAM, process, CUDA residual or "
                   "live-snapshot containers): every segment's SHA-256, the segment table, the metadata and the "
                   "evidence fingerprint recorded at acquisition.")
    METHOD = ("Re-reads each segment and compares its SHA-256 and table entry with the metadata; recomputes the "
              "SHA-256 over all data against data_sha256; checks the header digest that covers the header fields, "
              "metadata and segment table (version 2 containers); --expected-fingerprint compares the evidence "
              "fingerprint with the value recorded outside the container at acquisition.")
    ANALOG = "(chain of custody; no direct Volatility analogue)"
    SOURCES = ("file",)
    REQUIREMENTS = [Requirement("expected_fingerprint", str, None,
                                "evidence fingerprint printed at acquisition (hex) to compare with")]

    def run(self):
        if self.ctx.container is None:
            raise RequirementError("verify needs a .keto container: use -f <evidence.keto>")
        cont = self.ctx.container
        rows = [(0, (r["segment"], r["space"], Address(r["address"]), r["length"], r["sha256"], r["ok"],
                     r.get("detail", ""))) for r in cont.verify()]
        want = (self.opts["expected_fingerprint"] or "").strip().lower()
        if want:
            ok = len(want) >= 32 and cont.fingerprint.startswith(want)
            rows.append((0, (-4, "fingerprint", Address(0), 0, cont.fingerprint, ok,
                             "matches the recorded fingerprint" if ok else
                             "DOES NOT MATCH the recorded fingerprint %s" % want)))
        return TreeGrid([("Segment", int), ("Space", str), ("Address", Address), ("Length", int), ("SHA256", str),
                         ("OK", bool), ("Detail", str)], rows)


class Timeliner(Plugin):
    NAME = "timeliner"
    CATEGORY = "framework"
    DESCRIPTION = ("Builds one time-sorted timeline from every plugin that produces timestamps (GPU processes, "
                   "accounting history, Xid errors, compute-cache files, acquisition metadata).")
    METHOD = ("Runs every plugin implementing TimeLinerInterface whose data source is available, collects "
              "(description, type, time) events and sorts them; --create-bodyfile writes a mactime body file. "
              "Sources that read the analyst machine's own files by default (JIT and shader caches) are only "
              "included when the evidence is this live system (--live).")
    ANALOG = "timeliner"
    SOURCES = ("image", "live")
    REQUIREMENTS = [Requirement("create_bodyfile", bool, False, "also write timeline.body (mactime format)"),
                    Requirement("plugin_filter", str, None, "only plugins whose name contains this")]

    def run(self):
        events = []
        meta = self.ctx.metadata
        if meta.get("created_utc"):
            events.append(("keto", "evidence acquired (%s)" % meta.get("acquisition", {}).get("method", "?"),
                           "Acquired", meta["created_utc"]))
        errors = []
        local = self.ctx.analyses_local_system()
        for name in sorted(PLUGINS):
            cls = PLUGINS[name]
            if cls is Timeliner or not issubclass(cls, TimeLinerInterface):
                continue
            if self.opts["plugin_filter"] and self.opts["plugin_filter"] not in name:
                continue
            if getattr(cls, "LOCAL_DEFAULTS", False) and not local:
                errors.append((name, "reads this analyst machine's files by default, which are not part of the "
                                     "evidence: run %s --path <collected directory> separately" % name))
                continue
            try:
                inst = cls(self.ctx, {})
                for desc, etype, when in inst.generate_timeline():
                    if when is not None:
                        events.append((name, desc, etype, when))
            except (RequirementError, UnsupportedError) as exc:
                errors.append((name, str(exc)))
        def key(e):
            w = e[3]
            return w if isinstance(w, str) else w.isoformat()
        events.sort(key=key)
        if self.opts["create_bodyfile"]:
            path = self.ctx.output_path("timeline.body")
            with open(path, "w", encoding="utf-8") as fh:
                for plugin, desc, etype, when in events:
                    ts = int(when.timestamp()) if hasattr(when, "timestamp") else 0
                    fh.write("0|[%s] %s - %s|0|0|0|0|0|%d|%d|%d|%d\n" % (plugin, etype, desc.replace("|", "/"),
                                                                          ts, ts, ts, ts))
        rows = [(0, (when, plugin, etype, desc)) for plugin, desc, etype, when in events]
        rows += [(0, (na("skipped"), n, "-", e)) for n, e in errors]
        return TreeGrid([("Time", object), ("Plugin", str), ("Type", str), ("Description", str)], rows)
