"""GPU address spaces, page tables, physical memory ownership and residual data."""

from __future__ import annotations

import os
import re

from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.scanners import RegexScanner, scan
from keto.framework.treegrid import Address, Bytes, Hex, TreeGrid, na
from keto.framework.util import entropy, human_size, iter_strings, printable_ratio
from keto.gpu import discovery, sass
from keto.gpu.gmmu import PEER, SYS_COH, SYS_NCOH, VID, coalesce


def pick_aspaces(ctx, selector):
    spaces = discovery.address_spaces(ctx)
    if selector is None:
        return spaces
    sel = str(selector).lower()
    out = [a for a in spaces if a.name == sel or ("%x" % a.pdb) == sel.replace("0x", "")]
    if not out:
        raise RequirementError("no address space %r (known: %s)" % (selector, ", ".join(a.name for a in spaces)))
    return out


def classify(data: bytes) -> str:
    """Short content hint for a block of memory."""
    if not data or data.count(0) == len(data):
        return "zero"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if sass.looks_like_code(data[:4096 - 4096 % 16]):
        return "SASS code"
    pr = printable_ratio(data[:4096])
    if pr > 0.9:
        return "text"
    ent = entropy(data[:65536])
    if ent > 7.5:
        return "high-entropy (compressed/encrypted/random)"
    if data[3::4][:1024].count(0xFF) > 900:
        return "RGBA/BGRA pixels?"
    return "data (entropy %.1f)" % ent


AS_REQ = Requirement("aspace", str, None, "address space name (as_<pdb>) or page directory base in hex")


class AddressSpaces(Plugin):
    NAME = "nvidia.addrspaces"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Lists every GPU virtual address space (one per GPU context) with its page directory, "
                   "page-table format, the channels using it and how much memory it maps per aperture.")
    METHOD = ("Collects page directory bases from validated instance blocks (RAMIN+0x200) and Volta+ "
              "subcontext tables (RAMIN+0x2A0, valid mask at +0x298), plus --pdb, and walks each with the "
              "profile's GMMU format (VER2 5-level / VER3 6-level).")
    ANALOG = "windows.vadinfo (per-process view) / layerwriter --list"

    def run(self):
        def rows():
            for a in discovery.address_spaces(self.ctx):
                by_ap = {}
                for m in a.mappings():
                    by_ap[m.aperture] = by_ap.get(m.aperture, 0) + m.size
                users = ", ".join("0x%x:%s" % (pa, label) if pa is not None else label for pa, label in a.sources)
                st = a.walker.stats
                yield 0, (a.name, Address(a.pdb), a.aperture, a.fmt.upper(), human_size(a.big_page_size),
                          len(a.mappings()), human_size(by_ap.get(VID, 0)),
                          human_size(by_ap.get(SYS_COH, 0) + by_ap.get(SYS_NCOH, 0)), human_size(by_ap.get(PEER, 0)),
                          users, "tables=%d unreadable=%d out_of_range=%d" % (st["tables"], st["unreadable_tables"],
                                                                             st["out_of_range"]))
        return TreeGrid([("AddressSpace", str), ("PDB", Address), ("Aperture", str), ("MMU", str),
                         ("BigPage", str), ("Pages", int), ("VidMem", str), ("SysMem", str), ("Peer", str),
                         ("UsedBy", str), ("Walk", str)], rows())


class Mappings(Plugin):
    NAME = "nvidia.mappings"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Lists the mapped regions of each GPU address space: VA range, physical backing and "
                   "aperture, page size, permissions (RO/RW/PRIV), PTE kind, and a content hint.")
    METHOD = ("Walks the GMMU page tables to leaf PTEs, coalesces VA- and PA-contiguous pages with identical "
              "attributes, and samples each region's first bytes (zero / text / SASS / ELF / entropy).")
    ANALOG = "windows.vadinfo / linux.proc.Maps / mac.proc_maps"
    REQUIREMENTS = [AS_REQ, Requirement("no_classify", bool, False, "skip content classification")]

    def run(self):
        def rows():
            for a in pick_aspaces(self.ctx, self.opts["aspace"]):
                for r in coalesce(a.mappings()):
                    m = r["first"]
                    hint = na("skipped")
                    if not self.opts["no_classify"]:
                        hint = classify(a.layer.read(r["va"], min(r["size"], 65536), pad=True)) \
                            if a.layer.is_valid(r["va"]) else na("backing not in image")
                    yield 0, (a.name, Address(r["va"]), Address(r["va"] + r["size"] - 1), human_size(r["size"]),
                              m.aperture, Address(r["pa"]), human_size(m.size), m.flags(), Hex(m.kind), hint)
        return TreeGrid([("AddressSpace", str), ("Start VA", Address), ("End VA", Address), ("Size", str),
                         ("Aperture", str), ("Physical", Address), ("Page", str), ("Flags", str), ("Kind", Hex),
                         ("Contents", str)], rows())


class PtWalk(Plugin):
    NAME = "nvidia.ptwalk"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = "Prints the raw page-table tree of a GPU address space: every PDE, dual PDE and PTE with its raw value."
    METHOD = ("Depth-first GMMU walk from the page directory base; decodes PDE aperture/address, dual-PDE "
              "big/small table pointers, PTE fields, and notes invalid/sparse entries and large-page anomalies.")
    ANALOG = "windows.vadwalk"
    REQUIREMENTS = [AS_REQ, Requirement("limit", int, 2000, "maximum rows")]

    def run(self):
        def rows():
            n = 0
            for a in pick_aspaces(self.ctx, self.opts["aspace"]):
                yield 0, (a.name, "PDB", -1, Address(a.pdb), Hex(0), Address(0), "root", a.fmt)
                for e in a.walker.events():
                    n += 1
                    if n > self.opts["limit"]:
                        return
                    if e.kind == "pte" and e.target is not None:
                        m = e.target
                        detail = "%s:0x%x %s kind=0x%x" % (m.aperture, m.pa, m.flags(), m.kind)
                    elif e.kind == "pde":
                        detail = "-> %s:0x%x" % e.target
                    elif e.kind == "dual":
                        big, small = e.target
                        detail = "big=%s small=%s" % ("%s:0x%x" % big if big else "-",
                                                      "%s:0x%x" % small if small else "-")
                    else:
                        detail = e.note
                    yield e.depth + 1, (a.name, e.level, e.index, Address(e.entry_pa), Hex(e.raw), Address(e.va),
                                        e.kind, detail)
        return TreeGrid([("AddressSpace", str), ("Level", str), ("Index", int), ("EntryPA", Address), ("Raw", Hex),
                         ("VA", Address), ("Kind", str), ("Decoded", str)], rows())


class MemMap(Plugin):
    NAME = "nvidia.memmap"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Shows the page-level virtual-to-physical map of a GPU address space and can dump all of its "
                   "readable memory to a file (with a map file giving each page's offset).")
    METHOD = ("Lists every leaf PTE (VA, PA, size, aperture); --dump reads each readable page through the "
              "GMMU layer and writes pages back to back, recording the file offset per page.")
    ANALOG = "windows.memmap / linux.proc.Maps --dump"
    REQUIREMENTS = [AS_REQ, Requirement("dump", bool, False, "write mapped memory to <aspace>.dmp in the output dir")]

    def run(self):
        spaces = pick_aspaces(self.ctx, self.opts["aspace"])

        def rows():
            for a in spaces:
                fh = None
                if self.opts["dump"]:
                    path = self.ctx.output_path(a.name + ".dmp")
                    fh = open(path, "wb")
                file_off = 0
                try:
                    for m in a.mappings():
                        readable = a.layer.is_valid(m.va, m.size)
                        off = na("not dumped")
                        if fh and readable:
                            fh.write(a.layer.read(m.va, m.size))
                            off = Hex(file_off)
                            file_off += m.size
                        yield 0, (a.name, Address(m.va), Address(m.pa), m.aperture, Hex(m.size), m.flags(), readable, off)
                finally:
                    if fh:
                        fh.close()
        return TreeGrid([("AddressSpace", str), ("VA", Address), ("PA", Address), ("Aperture", str), ("Size", Hex),
                         ("Flags", str), ("Readable", bool), ("FileOffset", Hex)], rows())


class VaMap(Plugin):
    NAME = "nvidia.vamap"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Shows how each GPU address space is used: which VA regions hold command rings, pushbuffers, "
                   "launch descriptors, kernel code, semaphores, host-memory windows, surfaces and plain data.")
    METHOD = ("Joins coalesced GMMU regions with what the command-stream analysis referenced (GPFIFO bases, "
              "pushbuffer segments, QMD addresses, program addresses, semaphore targets, copy endpoints) and "
              "with PTE aperture/kind.")
    ANALOG = "windows.virtmap"
    REQUIREMENTS = [AS_REQ]

    def run(self):
        refs = {}
        for cc in discovery.channel_commands(self.ctx):
            if cc.aspace is None:
                continue
            tag = refs.setdefault(cc.aspace.name, [])
            tag.append((cc.ib.gp_base_va, "GPFIFO ring"))
            for s in cc.segments:
                tag.append((s["va"], "pushbuffer"))
                for ev in s["events"]:
                    d = ev.details
                    if ev.kind == "launch":
                        tag.append((d["qmd_va"], "launch descriptor (QMD)"))
                    elif ev.kind == "semaphore":
                        tag.append((d["address"], "semaphore"))
                    elif ev.kind == "copy" and d["src_type"] == "VIRTUAL":
                        tag.append((d["src"], "copy source"))
                    elif ev.kind == "copy" and d["dst_type"] == "VIRTUAL":
                        tag.append((d["dst"], "copy destination"))
                    elif ev.kind == "inline":
                        tag.append((d["dst"], "inline upload target"))
        for ln in discovery.launches(self.ctx):
            if ln.program_va is not None and ln.channel.aspace:
                refs.setdefault(ln.channel.aspace.name, []).append((ln.program_va, "kernel code"))

        def rows():
            for a in pick_aspaces(self.ctx, self.opts["aspace"]):
                tags = refs.get(a.name, [])
                for r in coalesce(a.mappings()):
                    m = r["first"]
                    uses = sorted({t for va, t in tags if r["va"] <= va < r["va"] + r["size"]})
                    if not uses:
                        if m.aperture != VID:
                            uses = ["host/peer memory window"]
                        elif m.kind:
                            uses = ["surface / non-pitch kind 0x%x" % m.kind]
                        else:
                            uses = ["data"]
                    yield 0, (a.name, Address(r["va"]), human_size(r["size"]), m.aperture, m.flags(), ", ".join(uses))
        return TreeGrid([("AddressSpace", str), ("Start VA", Address), ("Size", str), ("Aperture", str),
                         ("Flags", str), ("Use", str)], rows())


class PhysMap(Plugin):
    NAME = "nvidia.physmap"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Maps physical VRAM ownership: which blocks are page tables, instance blocks, mapped by which "
                   "address spaces, or unmapped (free) - and whether unmapped blocks still hold data.")
    METHOD = ("Builds a per-block index from the page-table walk (table pages and leaf targets) and instance "
              "block scan, then samples every block of --granularity bytes for zero/non-zero content and entropy; "
              "consecutive blocks with the same state are merged into one row.")
    ANALOG = "windows.bigpools / windows.poolscanner (physical view)"
    REQUIREMENTS = [Requirement("granularity", "size", 0x10000, "block size (default 64K)"),
                    Requirement("unmapped_only", bool, False, "only show unmapped blocks that contain data")]

    def run(self):
        vram = self.ctx.require_vram()
        g = self.opts["granularity"]
        owner = {}
        for ib in discovery.instance_blocks(self.ctx):
            owner.setdefault(ib.pa // g, set()).add("instance-block")
        for a in discovery.address_spaces(self.ctx):
            for e in a.walker.events():
                if e.entry_pa is not None:
                    owner.setdefault(e.entry_pa // g, set()).add("page-table")
            for m in a.mappings():
                if m.aperture == VID:
                    for blk in range(m.pa // g, (m.pa + m.size - 1) // g + 1):
                        owner.setdefault(blk, set()).add("mapped:" + a.name)

        def state(blk, data):
            o = owner.get(blk)
            if o:
                return ",".join(sorted(o))
            return "unmapped-zero" if data.count(0) == len(data) else "unmapped-data"

        def rows():
            run = None
            for start, length in vram.ranges():
                for off in range(start - start % g, start + length, g):
                    data = vram.read(off, g, pad=True)
                    st = state(off // g, data)
                    ent = entropy(data) if st == "unmapped-data" else None
                    if run and run[2] == st and run[1] == off:
                        run[1] = off + g
                        if ent is not None:
                            run[3] = max(run[3] or 0.0, ent)
                        continue
                    if run:
                        yield run
                    run = [off, off + g, st, ent]
            if run:
                yield run

        def out():
            for s, e, st, ent in rows():
                if self.opts["unmapped_only"] and st != "unmapped-data":
                    continue
                yield 0, (Address(s), Address(e - 1), human_size(e - s), st,
                          round(ent, 2) if ent is not None else na(""))
        return TreeGrid([("Start PA", Address), ("End PA", Address), ("Size", str), ("State", str),
                         ("MaxEntropy", float)], out())


class Residual(Plugin):
    NAME = "nvidia.residual"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Lists data left in VRAM that no page table maps (freed allocations: GPU memory remanence), "
                   "classified by content, and can dump each region.")
    METHOD = ("Uses the nvidia.physmap ownership index at 4 KiB granularity; contiguous unmapped non-zero pages "
              "form regions, classified by magic numbers, SASS density, printable ratio and entropy.")
    ANALOG = "windows.mftscan.ResidentData (recover data the OS no longer tracks)"
    REQUIREMENTS = [Requirement("dump", bool, False, "write each region to the output dir"),
                    Requirement("min_size", "size", 1, "ignore regions smaller than this")]

    def run(self):
        grid = PhysMap(self.ctx, {"granularity": 0x1000, "unmapped_only": True}).run()
        vram = self.ctx.require_vram()

        def rows():
            for _, (start, end, size, st, ent) in grid.rows:
                length = int(end) - int(start) + 1
                if length < self.opts["min_size"]:
                    continue
                data = vram.read(int(start), min(length, 1 << 20), pad=True)
                first = data.lstrip(b"\x00")
                lead = len(data) - len(first)
                path = na("")
                if self.opts["dump"]:
                    path = self.ctx.output_path("residual_%x.bin" % int(start))
                    with open(path, "wb") as fh:
                        fh.write(vram.read(int(start), length, pad=True))
                yield 0, (Address(start), human_size(length), classify(first[:65536]), ent,
                          Bytes(first[:64]), Address(int(start) + lead), path)
        return TreeGrid([("Start PA", Address), ("Size", str), ("Content", str), ("Entropy", float),
                         ("Preview", Bytes), ("FirstData", Address), ("Dumped", str)], rows())


class SysmemMap(Plugin):
    NAME = "nvidia.sysmemmap"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Lists GPU mappings of host (system) memory and of peer GPUs' memory - the windows through "
                   "which a GPU context can read or write CPU RAM by DMA.")
    METHOD = ("Selects leaf PTEs whose aperture is SYSTEM_COHERENT/NON_COHERENT (host physical address) or "
              "PEER (peer id + address); when a host RAM image is supplied (--host-image) the page is read "
              "through it and previewed.")
    ANALOG = "windows.symlinkscan (links out of the object namespace) / netscan for peer links"

    def run(self):
        sysmem = self.ctx.layers.get("sysmem")

        def rows():
            for a in discovery.address_spaces(self.ctx):
                for r in coalesce(a.mappings()):
                    m = r["first"]
                    if m.aperture == VID:
                        continue
                    preview = na("no --host-image")
                    if m.aperture != PEER and sysmem is not None:
                        preview = Bytes(sysmem.read(r["pa"], 48, pad=True)) if sysmem.is_valid(r["pa"]) else \
                            na("host page not in host image")
                    yield 0, (a.name, Address(r["va"]), human_size(r["size"]), m.aperture,
                              Address(r["pa"]), m.peer_id if m.aperture == PEER else na(""), m.flags(), preview)
        return TreeGrid([("AddressSpace", str), ("VA", Address), ("Size", str), ("Aperture", str),
                         ("Host/Peer PA", Address), ("PeerID", int), ("Flags", str), ("Preview", Bytes)], rows())


class VaRegexScan(Plugin):
    NAME = "nvidia.varegexscan"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = "Regex-scans the memory of every GPU address space (by virtual address)."
    METHOD = "Runs a compiled bytes regex over each GMMU layer's readable runs, reporting VA and physical backing."
    ANALOG = "windows.vadregexscan / linux.vmaregexscan"
    REQUIREMENTS = [Requirement("pattern", str, None, "regular expression (Python syntax, applied to bytes)"),
                    AS_REQ, Requirement("max_length", int, 256, "maximum match length")]

    def run(self):
        if not self.opts["pattern"]:
            raise RequirementError("--pattern is required")
        rx = re.compile(self.opts["pattern"].encode(), re.DOTALL)

        def rows():
            for a in pick_aspaces(self.ctx, self.opts["aspace"]):
                for va, m in scan(a.layer, RegexScanner(rx, max_length=self.opts["max_length"])):
                    t = a.translate(va)
                    yield 0, (a.name, Address(va), Address(t[1]) if t else na(""), t[0].aperture if t else "-",
                              Bytes(m.group()[:self.opts["max_length"]]))
        return TreeGrid([("AddressSpace", str), ("VA", Address), ("PA", Address), ("Aperture", str),
                         ("Match", Bytes)], rows())


class VaYaraScan(Plugin):
    NAME = "nvidia.vayarascan"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = "YARA-scans the memory of every GPU address space (by virtual address)."
    METHOD = ("Compiles --yara-rules/--yara-file with yara-python (optional dependency) and scans each GMMU "
              "layer chunk by chunk, translating hit offsets back to VAs and physical addresses.")
    ANALOG = "windows.vadyarascan / linux.vmayarascan"
    REQUIREMENTS = [Requirement("yara_rules", str, None, "inline rule text or a bare string to search"),
                    Requirement("yara_file", str, None, "path to a .yar rules file"), AS_REQ,
                    Requirement("builtin", bool, False, "use the bundled GPU threat rules (keto/rules)")]

    def run(self):
        from keto.plugins.core import compile_yara, yara_hits
        rules = compile_yara(self.opts["yara_rules"], self.opts["yara_file"], self.opts["builtin"])

        def rows():
            for a in pick_aspaces(self.ctx, self.opts["aspace"]):
                for va, rule, ident, data in yara_hits(rules, a.layer):
                    t = a.translate(va)
                    yield 0, (a.name, Address(va), Address(t[1]) if t else na(""), rule, ident, Bytes(data[:64]))
        return TreeGrid([("AddressSpace", str), ("VA", Address), ("PA", Address), ("Rule", str), ("String", str),
                         ("Data", Bytes)], rows())


class Strings(Plugin):
    NAME = "nvidia.strings"
    CATEGORY = "nvidia.memory"
    DESCRIPTION = ("Tells you which GPU address space / virtual address (or which structure) each string in VRAM "
                   "belongs to; reads a `strings -t d` style file or extracts strings itself.")
    METHOD = ("Builds a physical->virtual reverse index of every GPU address space and resolves each string's "
              "physical offset; unmapped offsets are labelled with the structure they fall in (instance block, "
              "cubin, residual).")
    ANALOG = "windows.strings"
    REQUIREMENTS = [Requirement("strings_file", str, None, "file of '<decimal offset> <string>' lines"),
                    Requirement("min_length", int, 8, "minimum length when extracting strings"),
                    Requirement("limit", int, 5000, "maximum strings")]

    def run(self):
        vram = self.ctx.require_vram()
        inst = {ib.pa: ib for ib in discovery.instance_blocks(self.ctx)}
        cub = [(c.offset, c.offset + c.size) for c in discovery.cubins(self.ctx) if c.layer == vram.name]

        def entries():
            if self.opts["strings_file"]:
                if not os.path.exists(self.opts["strings_file"]):
                    raise RequirementError("strings file not found")
                with open(self.opts["strings_file"], "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2 and parts[0].isdigit():
                            yield int(parts[0]), parts[1]
            else:
                for off, data, payload in vram.iter_chunks(4 << 20, 256):
                    for o, enc, text in iter_strings(data, self.opts["min_length"], utf16=False):
                        if o < payload:
                            yield off + o, text

        def where(pa):
            hits = discovery.reverse_lookup_all(self.ctx, pa)
            if hits:
                return "; ".join("%s:0x%x" % (a.name, va) for a, va, _ in hits)
            if (pa & ~0xFFF) in inst:
                return "instance block 0x%x" % (pa & ~0xFFF)
            for s, e in cub:
                if s <= pa < e:
                    return "cubin @0x%x" % s
            return "unmapped (residual)"

        def rows():
            for i, (pa, text) in enumerate(entries()):
                if i >= self.opts["limit"]:
                    break
                yield 0, (Address(pa), where(pa), text[:200])
        return TreeGrid([("PA", Address), ("Owner", str), ("String", str)], rows())
