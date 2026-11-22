"""Channels, timeslice groups and the scheduler's view (the GPU's 'processes')."""

from __future__ import annotations

from keto.framework.exceptions import RequirementError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, Bytes, TreeGrid, na
from keto.gpu import discovery
from keto.plugins.nvidia._common import aspace_name, channel_label, runlist_membership


class ChanScan(Plugin):
    NAME = "nvidia.chanscan"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Finds GPU channel instance blocks (the per-channel hardware context), including channels "
                   "that are no longer scheduled.")
    METHOD = ("Checks the RAMFC signature word (NV_PPBDMA_SIGNATURE_HW_VALID = 0xFACE at +0x10) of every "
              "4 KiB-aligned page, then validates the page directory base (+0x200; inside VRAM or a 52-bit host "
              "address), the GPFIFO base/size (+0x48; reserved bits zero, saved GP_GET/GP_PUT inside the ring), "
              "the USERD pointer (up to Turing; from Ampere on it comes from the runlist entry) and every "
              "subcontext page directory marked valid; USERD is read for the live GP_GET/GP_PUT.")
    ANALOG = "windows.psscan / linux.psscan"
    REQUIREMENTS = [Requirement("all", bool, False, "also show signature hits that fail validation")]

    def run(self):
        ibs = discovery.instance_blocks(self.ctx, include_invalid=self.opts["all"])
        rlm = runlist_membership(self.ctx)
        # Ampere+ RAMFC holds no USERD: only a runlist entry names it
        no_userd = na("not in a runlist (RAMFC holds no USERD from Ampere on)"
                      if "userd_lo" not in self.ctx.profile.ramfc else "no USERD pointer")

        def rows():
            for ib in ibs:
                a = discovery.address_space_of(self.ctx, ib) if ib.valid else None
                rl = rlm.get(ib.pa)
                yield 0, (Address(ib.pa), ib.chid_hint if ib.chid_hint is not None else na("n/a"),
                          rl[1] if rl else na("not in runlist"), ib.pdb_aperture or "-", Address(ib.pdb),
                          aspace_name(a), Address(ib.gp_base_va), ib.gp_entries,
                          ib.gp_get() if ib.gp_get() is not None else na("USERD unreadable"),
                          ib.gp_put() if ib.gp_put() is not None else na("USERD unreadable"),
                          Address(ib.userd_addr) if ib.userd_addr and ib.userd_aperture else no_userd,
                          ib.privileged, len(ib.subcontexts), ib.score, ib.valid)
        return TreeGrid([("InstanceBlock", Address), ("ChID", int), ("TSG", int), ("PDB Aperture", str),
                         ("PDB", Address), ("AddressSpace", str), ("GPFIFO VA", Address), ("Entries", int),
                         ("GP_GET", int), ("GP_PUT", int), ("USERD", Address), ("Privileged", bool),
                         ("Subcontexts", int), ("Score", int), ("Valid", bool)], rows())


def _entry_details(c) -> str:
    if c.userd_aperture is not None:  # Volta+ entries carry USERD
        return "%s USERD 0x%x" % (c.userd_aperture, c.userd_addr)
    if c.userd_addr is None:          # Kepler: instance block found through its CHID
        return "instance resolved by CHID" if c.inst_addr is not None else "CHID claimed by several instance blocks"
    return "USERD in RAMFC"


class RunlistPlugin(Plugin):
    NAME = "nvidia.runlist"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Lists the scheduler's runlists: every timeslice group (TSG) and the channels it schedules, "
                   "with each channel's instance block and USERD.")
    METHOD = ("Volta+: signature-scans 16-byte NV_RAMRL_ENTRY TSG headers (TYPE=1, sane timeslice, length 1..128, "
              "word3=0) and validates the channel entries (INST_PTR, USERD_PTR, CHID). Maxwell/Pascal: anchors on "
              "each instance block's address >> 12 in word1 of 8-byte entries and walks back to the TSG header. "
              "Kepler: entries hold only a CHID, so groups are anchored on CHIDs that instance blocks carry in RAMFC "
              "and each channel is resolved through that CHID. Contiguous groups are chained into runlists.")
    ANALOG = "windows.pslist (list walking) / linux.pidhashtable"

    def run(self):
        known = {ib.pa for ib in discovery.instance_blocks(self.ctx)}

        def rows():
            for rl in discovery.runlists(self.ctx):
                yield 0, ("runlist", Address(rl.pa), na(""), na(""), na(""), na(""), na(""), na(""))
                for g in rl.groups:
                    h = g.header
                    yield 1, ("TSG", Address(h.pa), h.tsgid, na(""), na(""), "%d channel(s)" % h.length,
                              "scale=%d timeout=%d" % (h.timeslice_scale, h.timeslice_timeout), na(""))
                    for c in g.channels:
                        yield 2, ("channel", Address(c.pa), h.tsgid, c.chid,
                                  Address(c.inst_addr) if c.inst_addr is not None else na("ambiguous CHID"),
                                  _entry_details(c), "runq=%d" % (c.runq or 0),
                                  c.inst_addr in known)
        return TreeGrid([("Kind", str), ("Offset", Address), ("TSG", int), ("ChID", int), ("InstanceBlock", Address),
                         ("Details", str), ("Scheduling", str), ("InstanceBlockFound", bool)], rows())


class ChanTree(Plugin):
    NAME = "nvidia.chantree"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Shows channels as a tree: GPU address space (one per process/context) -> channels -> "
                   "subcontexts (VEIDs), so engines working for the same process are grouped.")
    METHOD = ("Groups validated instance blocks by the page directory they (or their Volta+ subcontext PDB "
              "entries at RAMIN+0x2A0) point at; TSG membership comes from the runlist scan.")
    ANALOG = "windows.pstree / linux.pstree"

    def run(self):
        rlm = runlist_membership(self.ctx)
        spaces = discovery.address_spaces(self.ctx)
        ibs = {ib.pa: ib for ib in discovery.instance_blocks(self.ctx)}

        def rows():
            for a in spaces:
                yield 0, (a.name, Address(a.pdb), a.aperture, na(""), na(""), "%d mapping(s)" % len(a.mappings()))
                mains = [pa for pa, label in a.sources if label == "main" and pa in ibs]
                for pa in mains:
                    ib = ibs[pa]
                    rl = rlm.get(pa)
                    yield 1, (channel_label(self.ctx, ib), Address(pa), "channel",
                              rl[1] if rl else na("not in runlist"),
                              "privileged" if ib.privileged else "user",
                              "GPFIFO 0x%x x%d" % (ib.gp_base_va, ib.gp_entries))
                    for sc in ib.subcontexts:
                        yield 2, ("veid%d" % sc.veid, Address(sc.pdb), "subcontext", na(""), sc.aperture,
                                  "same AS" if sc.pdb == a.pdb else "AS 0x%x" % sc.pdb)
        return TreeGrid([("Node", str), ("Address", Address), ("Kind", str), ("TSG", int), ("Mode", str),
                         ("Details", str)], rows())


class TsgList(Plugin):
    NAME = "nvidia.tsglist"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = "Lists timeslice groups (TSGs) and their member channels with per-channel ring state."
    METHOD = ("Reads TSG headers and member channel entries from the runlist scan and joins each member with "
              "its decoded instance block (GPFIFO, GP_GET/GP_PUT, address space).")
    ANALOG = "windows.joblinks"

    def run(self):
        ibs = {ib.pa: ib for ib in discovery.instance_blocks(self.ctx)}

        def rows():
            for rl in discovery.runlists(self.ctx):
                for g in rl.groups:
                    yield 0, (g.header.tsgid, len(g.channels), na(""), na(""), na(""), na(""))
                    for c in g.channels:
                        ib = ibs.get(c.inst_addr)
                        a = discovery.address_space_of(self.ctx, ib) if ib else None
                        yield 1, (g.header.tsgid, c.chid, Address(c.inst_addr), aspace_name(a),
                                  ib.gp_get() if ib and ib.gp_get() is not None else na("unknown"),
                                  ib.gp_put() if ib and ib.gp_put() is not None else na("unknown"))
        return TreeGrid([("TSG", int), ("Members/ChID", int), ("InstanceBlock", Address), ("AddressSpace", str),
                         ("GP_GET", int), ("GP_PUT", int)], rows())


class Timeslices(Plugin):
    NAME = "nvidia.timeslices"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Reports each TSG's scheduling timeslice and flags groups configured far above the driver "
                   "default (GPU monopolisation by cryptojackers or denial-of-service workloads).")
    METHOD = ("Decodes NV_RAMRL_ENTRY_TSG_TIMESLICE_SCALE (19:16) and TIMEOUT (31:24); the effective slice is "
              "TIMEOUT << SCALE ticks. The driver default is TIMEOUT=128, SCALE=3.")
    ANALOG = "windows.timers / mac.timers"
    REQUIREMENTS = [Requirement("factor", int, 8, "flag slices this many times above the default")]

    def run(self):
        if self.opts["factor"] < 1:
            raise RequirementError("--factor must be at least 1")
        default = 128 << 3

        def rows():
            for rl in discovery.runlists(self.ctx):
                for g in rl.groups:
                    h = g.header
                    ticks = h.timeslice_ticks
                    yield 0, (h.tsgid, Address(h.pa), h.timeslice_timeout, h.timeslice_scale, ticks,
                              round(ticks / default, 2), ticks >= default * self.opts["factor"])
        return TreeGrid([("TSG", int), ("Entry", Address), ("Timeout", int), ("Scale", int), ("Ticks", int),
                         ("xDefault", float), ("Suspicious", bool)], rows())


class Gpfifo(Plugin):
    NAME = "nvidia.gpfifo"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Lists every GPFIFO (command submission ring) entry of every channel: pushbuffer segment "
                   "address, length, whether the GPU already consumed it, and what it contains.")
    METHOD = ("Reads the ring at RAMFC GP_BASE (size 1 << LIMIT2) through the channel's GPU address space; "
              "decodes NVC56F_GP_ENTRY0/1 (GET, GET_HI, LENGTH, LEVEL, SYNC) and classifies each entry against "
              "USERD GP_GET/GP_PUT.")
    ANALOG = "windows.threads / linux.pslist (threads)"
    REQUIREMENTS = [Requirement("channel", "address", None, "only the channel with this instance block address")]

    def run(self):
        def rows():
            for cc in discovery.channel_commands(self.ctx):
                if self.opts["channel"] is not None and cc.ib.pa != self.opts["channel"]:
                    continue
                yield 0, (channel_label(self.ctx, cc.ib), na(""), na(""), na(""), na(""), na(""),
                          cc.error or "%d entr%s" % (len(cc.gp_entries), "y" if len(cc.gp_entries) == 1 else "ies"))
                for seg in cc.segments:
                    e = seg["entry"]
                    kinds = {}
                    for ev in seg["events"]:
                        kinds[ev.kind] = kinds.get(ev.kind, 0) + 1
                    summary = ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())) or \
                        ("control opcode %d" % e.opcode if e.is_control else
                         ("%d method(s)" % len(seg["methods"]) if seg["readable"] else "unreadable"))
                    yield 1, (channel_label(self.ctx, cc.ib), e.index, Address(e.va), e.nbytes, seg["state"],
                              "%s/%s" % (e.level, e.sync), summary)
        return TreeGrid([("Channel", str), ("Index", int), ("Pushbuffer VA", Address), ("Bytes", int),
                         ("State", str), ("Level/Sync", str), ("Contents", str)], rows())


class Pending(Plugin):
    NAME = "nvidia.pending"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Lists channels with submitted-but-unexecuted work (GP_GET != GP_PUT) at acquisition time, "
                   "and the commands that were about to run.")
    METHOD = ("Compares USERD GP_GET/GP_PUT (falling back to the RAMFC copies) and reports the ring entries in "
              "[GP_GET, GP_PUT) with their decoded events.")
    ANALOG = "windows.suspended_threads"

    def run(self):
        def rows():
            for cc in discovery.channel_commands(self.ctx):
                ib = cc.ib
                get, put = ib.gp_get(), ib.gp_put()
                if get is None or put is None or get == put:
                    continue
                pend = [s for s in cc.segments if s["state"] == "pending"]
                yield 0, (channel_label(self.ctx, ib), get, put, len(pend), na(""))
                for s in pend:
                    for ev in s["events"]:
                        desc = ", ".join("%s=%s" % (k, ("0x%x" % v) if isinstance(v, int) and not isinstance(v, bool)
                                                    else v) for k, v in ev.details.items() if k != "data")
                        yield 1, (channel_label(self.ctx, ib), get, put, s["entry"].index, "%s: %s" % (ev.kind, desc))
        return TreeGrid([("Channel", str), ("GP_GET", int), ("GP_PUT", int), ("Pending/Index", int),
                         ("Event", str)], rows())


class Privileges(Plugin):
    NAME = "nvidia.privileges"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Reports privileged channels (kernel/RM channels) and privileged page mappings, flagging "
                   "privileged pages inside address spaces used by unprivileged channels.")
    METHOD = ("Reads the RAMFC HCE_CTRL privilege bit (bit 5) of each instance block and the PTE PRIVILEGE bit "
              "(VER2 bit 5; VER3 PCF bit 1) of every mapping in each address space.")
    ANALOG = "windows.privileges / linux.capabilities"

    def run(self):
        ibs = discovery.instance_blocks(self.ctx)

        def rows():
            for a in discovery.address_spaces(self.ctx):
                users = [ib for ib in ibs if (ib.pa, "main") in a.sources]
                user_mode = any(not ib.privileged for ib in users)
                for ib in users:
                    yield 0, ("channel", channel_label(self.ctx, ib), a.name, Address(ib.pa), ib.privileged, False)
                for m in a.mappings():
                    if m.privileged:
                        yield 0, ("mapping", "%s %s" % (m.flags(), m.aperture), a.name, Address(m.va), True, user_mode)
        return TreeGrid([("Kind", str), ("Object", str), ("AddressSpace", str), ("Address", Address),
                         ("Privileged", bool), ("PrivInUserAS", bool)], rows())


class EngineContexts(Plugin):
    NAME = "nvidia.contexts"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Shows, per channel, where the engine's saved execution state lives: the context-switch image "
                   "(the GPU's equivalent of saved CPU registers), its addressing mode, the subcontext (VEID), "
                   "PASID/ATS binding and the engine method buffer, with a preview of the saved state.")
    METHOD = ("Decodes NV_RAMIN_ENGINE_WFI (TARGET 1:0, MODE 2 physical/virtual, CS 3 WFI/FG, PTR 31:12 + HI), "
              "NV_RAMIN_ENGINE_WFI_VEID, NV_RAMIN_PASID / ENABLE_ATS and NV_RAMIN_ENG_METHOD_BUFFER_ADDR; virtual "
              "pointers are translated through the channel's page tables and the first bytes are read.")
    ANALOG = "windows.kpcrs / thread context (saved register state)"

    def run(self):
        def rows():
            for ib in discovery.instance_blocks(self.ctx):
                w = ib.engine_wfi or {}
                ptr = w.get("ptr", 0)
                a = discovery.address_space_of(self.ctx, ib)
                where, preview = na("no context pointer"), na("")
                if ptr:
                    if w.get("mode") == "virtual":
                        t = a.translate(ptr) if a else None
                        where = "%s:0x%x" % (t[0].aperture, t[1]) if t else "UNMAPPED"
                        if t:
                            preview = Bytes(a.layer.read(ptr, 64, pad=True))
                    else:
                        where = "%s:0x%x" % (w.get("target"), ptr)
                        if w.get("target") == "vidmem" and self.ctx.vram is not None:
                            preview = Bytes(self.ctx.vram.read(ptr, 64, pad=True))
                yield 0, (channel_label(self.ctx, ib), Address(ib.pa), w.get("mode", "-"), w.get("cs", "-"),
                          Address(ptr), where, ib.veid if ib.veid is not None else na(""),
                          ib.pasid if ib.pasid is not None else na(""), ib.ats, Address(ib.method_buffer), preview)
        return TreeGrid([("Channel", str), ("InstanceBlock", Address), ("Mode", str), ("CtxSwitch", str),
                         ("EngineCtx", Address), ("Resolves to", str), ("VEID", int), ("PASID", int), ("ATS", bool),
                         ("MethodBuffer", Address), ("SavedState", Bytes)], rows())


class OrphanChannels(Plugin):
    NAME = "nvidia.orphanchans"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = ("Finds channels whose own structures do not resolve: GPFIFO, USERD or page directory outside "
                   "VRAM or unmapped in the channel's address space (stale, corrupted or forged contexts).")
    METHOD = ("For each signature-valid instance block, translates GP_BASE through its address space, checks "
              "USERD lies inside VRAM, and checks the page directory walk produced at least one mapping.")
    ANALOG = "windows.orphan_kernel_threads"

    def run(self):
        vram = self.ctx.vram_size or 0

        def rows():
            for ib in discovery.instance_blocks(self.ctx):
                a = discovery.address_space_of(self.ctx, ib)
                problems = []
                if a is None or not a.mappings():
                    problems.append("address space has no mappings")
                elif a.translate(ib.gp_base_va) is None:
                    problems.append("GPFIFO VA 0x%x unmapped" % ib.gp_base_va)
                if ib.userd_aperture == "vidmem" and vram and ib.userd_addr >= vram:
                    problems.append("USERD beyond VRAM")
                if not ib.userd:
                    problems.append("USERD unreadable")
                if problems:
                    yield 0, (channel_label(self.ctx, ib), Address(ib.pa), "; ".join(problems))
        return TreeGrid([("Channel", str), ("InstanceBlock", Address), ("Problems", str)], rows())
