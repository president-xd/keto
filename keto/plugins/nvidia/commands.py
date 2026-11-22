"""GPU command streams: what each channel told the GPU to do."""

from __future__ import annotations

import datetime as _dt
import struct

from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.scanners import AnchoredScanner, byte_prefilter, scan, scan_aligned_u32
from keto.framework.treegrid import Address, Bytes, Hex, TreeGrid, na
from keto.gpu import discovery, pushbuf, qmd as qmd_fmt
from keto.gpu.gmmu import VID
from keto.plugins.nvidia._common import channel_label

CHANNEL_REQ = Requirement("channel", "address", None, "only the channel with this instance block address")


def _fmt(details: dict) -> str:
    parts = []
    for k, v in details.items():
        if k == "data":
            continue
        if isinstance(v, bool) or not isinstance(v, int):
            parts.append("%s=%s" % (k, v))
        else:
            parts.append("%s=0x%x" % (k, v))
    return " ".join(parts)


def _selected(ctx, opts):
    for cc in discovery.channel_commands(ctx):
        if opts.get("channel") is None or cc.ib.pa == opts["channel"]:
            yield cc


class PushBuf(Plugin):
    NAME = "nvidia.pushbuf"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Decodes every channel's command history: each pushbuffer method write with its engine "
                   "class and method name (the GPU equivalent of recovering console command history).")
    METHOD = ("GPFIFO entry -> pushbuffer VA -> GMMU translation -> method headers (SEC_OP 31:29, COUNT 28:16, "
              "SUBCHANNEL 15:13, ADDRESS 11:0); subchannel->class bindings come from SET_OBJECT, method names "
              "from the class database (host methods < 0x100 apply to every subchannel).")
    ANALOG = "windows.consoles / windows.cmdscan / linux.bash"
    REQUIREMENTS = [CHANNEL_REQ, Requirement("events_only", bool, False, "show decoded events, not raw methods")]

    def run(self):
        db = self.ctx.classdb

        def rows():
            for cc in _selected(self.ctx, self.opts):
                label = channel_label(self.ctx, cc.ib)
                bind = {}
                for seg in cc.segments:
                    if self.opts["events_only"]:
                        for ev in seg["events"]:
                            yield 0, (label, seg["entry"].index, Address(ev.offset), ev.subch,
                                      db.class_name(ev.class_id) if ev.class_id else "-", ev.kind, _fmt(ev.details))
                        continue
                    for m in seg["methods"]:
                        if m.method == 0:  # SET_OBJECT
                            bind[m.subch] = m.value & 0xFFFF
                        fam = db.family(bind.get(m.subch))
                        cname = db.class_name(bind[m.subch]) if m.subch in bind else "-"
                        yield 0, (label, seg["entry"].index, Address(m.offset), m.subch, cname,
                                  db.method_name(fam, m.method), "0x%08x (%s)" % (m.value, m.op))
        return TreeGrid([("Channel", str), ("GPFIFO", int), ("VA", Address), ("SubCh", int), ("Class", str),
                         ("Method/Event", str), ("Value/Details", str)], rows())


class PbScan(Plugin):
    NAME = "nvidia.pbscan"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Finds command streams anywhere in physical memory, including stale pushbuffers no live "
                   "channel references (history of past GPU work).")
    METHOD = ("Signature-scans for a SET_OBJECT method (INC/NON_INC/ONE_INC header, count 1, method 0) whose "
              "value is a known engine class id, decodes forward until the stream becomes invalid, scores the "
              "stream by known-method ratio, and checks whether any channel's GPFIFO points at it.")
    ANALOG = "windows.cmdscan (scanning variant)"
    REQUIREMENTS = [Requirement("min_methods", int, 3, "minimum decoded methods to report"),
                    Requirement("window", "size", 0x4000, "bytes decoded after each signature")]

    def run(self):
        layer = self.ctx.primary
        db = self.ctx.classdb
        referenced = []  # (start, end, instance block of the channel whose GPFIFO points there)
        try:
            for cc in discovery.channel_commands(self.ctx):
                for s in cc.segments:
                    if s["pa"] is not None:
                        referenced.append((s["pa"], s["pa"] + s["length"], cc.ib.pa))
        except Exception:
            pass

        def owner(addr):
            return next((ch for s, e, ch in referenced if s <= addr < e), None)

        def segment_start(addr):
            return min(s for s, e, ch in referenced if s <= addr < e)

        sc = AnchoredScanner([b"\x01\x20", b"\x01\x60", b"\x01\xa0"], pushbuf.SET_OBJECT_RE, before=2, after=8)
        sc.alignment = 4
        if self.opts["window"] <= 0 or self.opts["min_methods"] < 1:
            raise RequirementError("--window must be > 0 and --min-methods >= 1")

        def rows():
            last_end = -1
            for off, m in sorted(scan(layer, sc), key=lambda h: h[0]):
                cls = int.from_bytes(m.group(1), "little")
                if cls not in db.classes or off < last_end:
                    continue
                data = layer.read(off, self.opts["window"], pad=True)
                st = pushbuf.DecodeStats()
                methods, events, _ = pushbuf.interpret(data, off, db, stats=st)
                # a stream does not run on into a segment another channel submitted (or, for a stray stream,
                # into any live segment): cut it there and decode it again
                first = owner(off)
                cut = next((x.offset for x in methods if owner(x.offset) not in (None, first)), None)
                if cut is not None:
                    data = data[:max(0, segment_start(cut) - off)]
                    st = pushbuf.DecodeStats()
                    methods, events, _ = pushbuf.interpret(data, off, db, stats=st)
                while methods and methods[-1].value == 0 and methods[-1].method == 0:
                    methods.pop()
                if len(methods) < self.opts["min_methods"]:
                    continue
                end = methods[-1].offset + 4
                last_end = end
                score = pushbuf.score_stream(data[:end - off], off, db)
                kinds = {}
                for ev in events:
                    kinds[ev.kind] = kinds.get(ev.kind, 0) + 1
                ref = owner(off) is not None
                yield 0, (Address(off), end - off, db.class_name(cls), len(methods), round(score["ratio"], 2),
                          ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())), ref)
        return TreeGrid([("Offset", Address), ("Bytes", int), ("FirstClass", str), ("Methods", int),
                         ("KnownRatio", float), ("Events", str), ("ReferencedByChannel", bool)], rows())


class Launches(Plugin):
    NAME = "nvidia.launches"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Lists compute kernel launches: which channel launched what code, grid/block shape, "
                   "registers, shared memory, constant buffers, and the kernel name when the code is known.")
    METHOD = ("For each SEND_PCAS_A (QMD address >> 8) in a compute-class stream, reads the QMD (256 or 384 bytes) "
              "through the channel's address space and decodes it with the layout of the version recorded in the "
              "descriptor itself (every published layout V00_06..V05_01; a V05_01 task is listed once per "
              "sub-task, each with its own program, grid, block, registers and constant banks; unknown versions "
              "shown raw), resolves PROGRAM_ADDRESS (PROGRAM_OFFSET + SET_PROGRAM_REGION_A/B on Kepler..Pascal), "
              "translates it and matches the physical address against located kernel code.")
    ANALOG = "windows.threads (start addresses) / linux.pscallstack"
    REQUIREMENTS = [CHANNEL_REQ]

    def run(self):
        def rows():
            for ln in discovery.launches(self.ctx):
                if self.opts["channel"] is not None and ln.channel.ib.pa != self.opts["channel"]:
                    continue
                q = ln.qmd
                label = channel_label(self.ctx, ln.channel.ib)
                if q is None:
                    yield 0, (label, Address(ln.event.details["qmd_va"]), na("unrecognised"), na("QMD not decoded"),
                              na(""), na(""), na(""), na(""), na(""), na(""),
                              Bytes(ln.qmd_raw[:64]) if ln.qmd_raw else na("unmapped"))
                    continue
                kname = ln.kernel.kernel.demangled if ln.kernel else na("unknown code")
                mapping = ln.program_mapping.flags() + " " + ln.program_mapping.aperture if ln.program_mapping \
                    else "UNMAPPED"
                cbs = ", ".join("cb%d@0x%x+0x%x" % cb for cb in q.constant_buffers()) or "-"
                version = q.version.upper()
                if "sub_tasks" in q.fields:  # V05_01: which sub-task of the task this row is
                    version += " sub-task %d/%d (%s)" % (q.sub_task, max(1, q.fields["sub_tasks"]), q.qmd_type)
                yield ln.sub_task and 1 or 0, (label, Address(ln.event.details["qmd_va"]), version,
                          Address(ln.program_va) if ln.program_va is not None else na("program region unknown"),
                          kname, mapping, "%dx%dx%d" % q.grid, "%dx%dx%d" % q.block, q.registers, q.shared_memory,
                          cbs)
        return TreeGrid([("Channel", str), ("QMD VA", Address), ("QMD", str), ("Program VA", Address),
                         ("Kernel", str), ("CodeMapping", str), ("Grid", str), ("Block", str), ("Regs", int),
                         ("Shared", int), ("ConstBuffers", object)], rows())


class QmdScan(Plugin):
    NAME = "nvidia.qmdscan"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Finds kernel launch descriptors (QMDs) anywhere in VRAM, including ones from past launches "
                   "no command stream references any more.")
    METHOD = ("Checks every 256-byte-aligned block for any published QMD version signature (byte 72 = major<<4|minor "
              "for V00_06..V04_01, byte 58 for V05_xx), decodes it with that version's layout and keeps plausible "
              "ones (1..1024 threads per block, non-zero grid, aligned program address/offset); marks those "
              "referenced by a launch. Works on VRAM, host RAM images and process dumps, Kepler to Blackwell.")
    ANALOG = "windows.thrdscan"

    def run(self):
        layer = self.ctx.primary
        referenced = set()
        if layer is self.ctx.vram:
            for ln in discovery.launches(self.ctx):
                t = ln.channel.aspace.translate(ln.event.details["qmd_va"]) if ln.channel.aspace else None
                if t and t[0].aperture == VID:
                    referenced.add(t[1])

        def rows():
            seen = set()
            for woff, mask, values in qmd_fmt.scan_signatures():
                for pa, _ in scan_aligned_u32(layer, woff, qmd_fmt.QMD_SIZE, lambda v: (v & mask) in values,
                                              prefilter=byte_prefilter(woff, mask, values)):
                    if pa in seen:
                        continue
                    raw = layer.read(pa, qmd_fmt.MAX_QMD_SIZE, pad=True)
                    q = qmd_fmt.decode(raw) if qmd_fmt.quick_plausible(raw) else None
                    if q is None or not q.plausible():
                        continue
                    seen.add(pa)
                    prog = Address(q.program_address) if q.program_address is not None else \
                        "offset 0x%x" % (q.program_offset or 0)
                    yield 0, (Address(pa), q.version.upper(), prog, "%dx%dx%d" % q.grid, "%dx%dx%d" % q.block,
                              q.registers, pa in referenced)
        return TreeGrid([("PA", Address), ("QMD", str), ("Program", object), ("Grid", str), ("Block", str),
                         ("Regs", int), ("Referenced", bool)], rows())


class Copies(Plugin):
    NAME = "nvidia.copies"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Lists copy-engine DMA transfers: source and destination (virtual or physical), where each end "
                   "really lives (VRAM / host RAM / peer GPU), size and layout.")
    METHOD = ("Interprets copy-class LAUNCH_DMA (0x300) with the latched OFFSET_IN/OUT, LINE_LENGTH_IN, LINE_COUNT, "
              "PITCH and SET_SRC/DST_PHYS_MODE state; virtual endpoints are translated through the channel's "
              "page tables to find their aperture.")
    ANALOG = "windows.dumpfiles (data movement) / netscan (data leaving the device)"
    REQUIREMENTS = [CHANNEL_REQ]

    def run(self):
        def where(cc, kind, addr, target):
            if kind == "PHYSICAL":
                return {"LOCAL_FB": "vidmem", "COHERENT_SYSMEM": "sysmem", "NONCOHERENT_SYSMEM": "sysmem",
                        "PEERMEM": "peer"}.get(target, target or "?") + " (physical)"
            t = cc.aspace.translate(addr) if cc.aspace else None
            return "%s:0x%x" % (t[0].aperture, t[1]) if t else "UNMAPPED"

        def rows():
            for cc in _selected(self.ctx, self.opts):
                for ev in cc.events:
                    if ev.kind != "copy":
                        continue
                    d = ev.details
                    yield 0, (channel_label(self.ctx, cc.ib), Address(d["src"]),
                              where(cc, d["src_type"], d["src"], d.get("src_target")), Address(d["dst"]),
                              where(cc, d["dst_type"], d["dst"], d.get("dst_target")), d["bytes"],
                              "%s->%s" % (d["src_layout"], d["dst_layout"]), d["semaphore"], d["interrupt"])
        return TreeGrid([("Channel", str), ("Source", Address), ("SourceIs", str), ("Destination", Address),
                         ("DestinationIs", str), ("Bytes", int), ("Layout", str), ("Semaphore", str),
                         ("Interrupt", str)], rows())


class Semaphores(Plugin):
    NAME = "nvidia.semaphores"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Lists GPU semaphore operations (acquire/release from host, compute and copy engines) and the "
                   "value currently stored at each semaphore address.")
    METHOD = ("Collects SEM_ADDR/SEM_PAYLOAD/SEM_EXECUTE (host), SET_REPORT_SEMAPHORE_A..D (compute), copy "
              "LAUNCH_DMA semaphore releases and the RELEASE0 semaphore of each launched QMD (kernel completion); "
              "reads the current 32-bit value through the channel's address space.")
    ANALOG = "windows.mutantscan"
    REQUIREMENTS = [CHANNEL_REQ]

    def run(self):
        def current(cc, addr):
            if cc.aspace and cc.aspace.translate(addr):
                return Hex(int.from_bytes(cc.aspace.layer.read(addr, 4, pad=True), "little"))
            return na("unmapped")

        def rows():
            for cc in _selected(self.ctx, self.opts):
                for ev in cc.events:
                    d = ev.details
                    if ev.kind == "semaphore":
                        addr, payload, op, eng = d["address"], d["payload"], d["op"], d["engine"]
                    elif ev.kind == "copy" and d.get("semaphore") not in (None, "NONE"):
                        addr, payload, op, eng = d["semaphore_address"], d["semaphore_payload"], d["semaphore"], "copy"
                    else:
                        continue
                    yield 0, (channel_label(self.ctx, cc.ib), eng, op, Address(addr), Hex(payload), current(cc, addr))
            for ln in discovery.launches(self.ctx):
                q = ln.qmd
                if q is None or not q.release_address or not q.fields.get("rel0_enable", 1):
                    continue
                if self.opts.get("channel") is not None and ln.channel.ib.pa != self.opts["channel"]:
                    continue
                op = "RELEASE_FOUR_WORD" if q.release_four_words else "RELEASE_ONE_WORD"
                yield 0, (channel_label(self.ctx, ln.channel.ib), "compute (QMD release)", op,
                          Address(q.release_address), Hex(q.release_payload), current(ln.channel, q.release_address))
        return TreeGrid([("Channel", str), ("Engine", str), ("Operation", str), ("Address", Address),
                         ("Payload", Hex), ("CurrentValue", Hex)], rows())


class GpuTimeline(Plugin, TimeLinerInterface):
    NAME = "nvidia.gputimeline"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Rebuilds a GPU-side timeline from the timestamps the GPU itself wrote: every semaphore release "
                   "that stores the 16-byte {payload, 64-bit PTIMER nanoseconds} structure (host, copy-engine and "
                   "compute releases, and kernel-completion releases named in launch descriptors).")
    METHOD = ("For host SEM_EXECUTE with RELEASE_TIMESTAMP (bit 25), pre-Volta SEMAPHORED releases with the 16-byte "
              "size, copy LAUNCH_DMA four-word semaphores, compute SET_REPORT_SEMAPHORE_D with STRUCTURE_SIZE four "
              "words, and QMD RELEASE0 four-word structures, reads the 16 bytes at the semaphore address through the "
              "channel's page tables: payload at +0, PTIMER ns at +8 (NV_PPBDMA manual layout). Work in GPFIFO entries "
              "still pending (between GP_GET and GP_PUT) has not run and is left out. PTIMER values in the "
              "Unix-epoch range are also shown as UTC.")
    ANALOG = "linux.boottime / timeliner (GPU clock)"

    @staticmethod
    def _utc(ns):
        if 946684800 * 10 ** 9 <= ns <= 4102444800 * 10 ** 9:  # 2000-01-01 .. 2100-01-01 when PTIMER holds epoch time
            return _dt.datetime.fromtimestamp(ns / 1e9, tz=_dt.timezone.utc)
        return None

    def _events(self):
        out = []
        for cc in discovery.channel_commands(self.ctx):
            if cc.aspace is None:
                continue
            label = channel_label(self.ctx, cc.ib)
            for seg in cc.segments:
                if seg["state"] == "pending":  # submitted but not executed yet: it wrote no timestamp
                    continue
                for ev in seg["events"]:
                    d = ev.details
                    if ev.kind == "semaphore" and d.get("timestamped"):
                        out.append((cc, label, d["address"], "%s semaphore %s (payload 0x%x)"
                                    % (d["engine"], d["op"], d["payload"])))
                    elif ev.kind == "copy" and d.get("semaphore_timestamped"):
                        out.append((cc, label, d["semaphore_address"], "copy 0x%x -> 0x%x (%d bytes) completed"
                                    % (d["src"], d["dst"], d["bytes"])))
        for ln in discovery.launches(self.ctx):
            q = ln.qmd
            if ln.state == "pending" or ln.sub_task:  # the release belongs to the task: report it once
                continue
            if q is not None and q.release_four_words and ln.channel.aspace is not None:
                name = ln.kernel.kernel.name if ln.kernel else "unknown kernel"
                out.append((ln.channel, channel_label(self.ctx, ln.channel.ib), q.release_address,
                            "kernel %s grid %dx%dx%d completed" % ((name,) + q.grid)))
        rows = []
        for cc, label, addr, desc in out:
            if not cc.aspace.translate(addr):
                rows.append((None, label, addr, desc, None, "semaphore page unmapped"))
                continue
            raw = cc.aspace.layer.read(addr, 16, pad=True)
            payload, ts = struct.unpack_from("<QQ", raw)
            rows.append((ts or None, label, addr, desc, payload, "" if ts else "no timestamp written yet"))
        rows.sort(key=lambda r: (r[0] is None, r[0] or 0))
        return rows

    def run(self):
        def rows():
            evs = self._events()
            base = next((r[0] for r in evs if r[0]), None)
            for ts, label, addr, desc, payload, note in evs:
                yield 0, (ts if ts is not None else na(note), (ts - base) / 1e6 if ts and base else na(""),
                          self._utc(ts) if ts else na(""), label, Address(addr), desc,
                          Hex(payload) if payload is not None else na(""))
        return TreeGrid([("GPU time (ns)", int), ("Delta (ms)", float), ("UTC (if PTIMER=epoch)", object),
                         ("Channel", str), ("Semaphore", Address), ("Event", str), ("Payload", Hex)], rows())

    def generate_timeline(self):
        for ts, label, addr, desc, payload, note in self._events():
            utc = self._utc(ts) if ts else None
            if utc:
                yield ("%s: %s" % (label, desc), "GPU", utc)


class Classes(Plugin):
    NAME = "nvidia.classes"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = ("Lists which engine classes each channel bound to its subchannels (compute, copy, 3D, video "
                   "encode/decode...), exposing unexpected engine use by a process.")
    METHOD = "Records every SET_OBJECT (host method 0x0000: CLASS_ID 15:0, ENGINE_ID 20:16) in each channel's stream."
    ANALOG = "windows.ssdt (dispatch-table view)"

    def run(self):
        db = self.ctx.classdb

        def rows():
            for cc in discovery.channel_commands(self.ctx):
                for ev in cc.events:
                    if ev.kind == "bind":
                        c = db.classes.get(ev.class_id, {})
                        yield 0, (channel_label(self.ctx, cc.ib), ev.subch, Hex(ev.class_id), ev.details["class"],
                                  ev.details["family"] or "?", c.get("verified", False))
        return TreeGrid([("Channel", str), ("SubCh", int), ("ClassID", Hex), ("Class", str), ("Engine", str),
                         ("IdVerified", bool)], rows())


class Notifiers(Plugin):
    NAME = "nvidia.notifiers"
    CATEGORY = "nvidia.commands"
    DESCRIPTION = "Lists GPU-to-CPU notifications requested by command streams (non-stall interrupts, awaken semaphores, copy interrupts)."
    METHOD = ("Collects host NON_STALL_INTERRUPT methods, compute report semaphores with AWAKEN_ENABLE (bit 20) "
              "and copy LAUNCH_DMA INTERRUPT_TYPE != NONE.")
    ANALOG = "windows.callbacks"

    def run(self):
        def rows():
            for cc in discovery.channel_commands(self.ctx):
                for ev in cc.events:
                    if ev.kind == "interrupt":
                        yield 0, (channel_label(self.ctx, cc.ib), Address(ev.offset), ev.details["engine"],
                                  ev.details["type"], _fmt(ev.details))
                    elif ev.kind == "copy" and ev.details["interrupt"] != "NONE":
                        yield 0, (channel_label(self.ctx, cc.ib), Address(ev.offset), "copy",
                                  "LAUNCH_DMA " + ev.details["interrupt"], "bytes=%d" % ev.details["bytes"])
        return TreeGrid([("Channel", str), ("At", Address), ("Engine", str), ("Type", str), ("Details", str)], rows())
