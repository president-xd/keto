"""Linux / WSL2 host kernel memory: GPU process tree of the WSL2 GPU paravirtualisation driver (dxgkrnl),
the task list with GPU device handles, and dumps of guest pages shared with the GPU."""

from __future__ import annotations

import os

from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.framework.layers import BytesLayer
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, TreeGrid, na
from keto.gpu import artifacts
from keto.hostmem import dxg
from keto.hostmem.session import HOST_REQS, kernel_memory


class _HostPlugin(Plugin):
    SOURCES = ("file",)  # host image via -f/--host-image (+ --btf/--kallsyms), or the running kernel (--kcore)
    CATEGORY = "host"

    def km(self):
        return kernel_memory(self.ctx, self.opts)


class KernelInfo(_HostPlugin):
    NAME = "host.kernel"
    DESCRIPTION = ("Identifies the imaged Linux kernel and how its memory is being read: banner, KASLR "
                   "offsets, paging mode and the source of symbols and types.")
    METHOD = ("phys_base: the value a kcore container recorded, or else the linux_banner string located in physical "
              "memory, accepted only when the image's phys_base variable and banner agree with it; with --kcore, "
              "the kernel-text segment's physical address. Reads page_offset_base and __pgtable_l5_enabled; "
              "types come from the kernel's own BTF.")
    ANALOG = "banners.Banners / linux kernel identification"
    REQUIREMENTS = HOST_REQS

    def run(self):
        km = self.km()
        meta = (self.ctx.host_metadata or self.ctx.metadata or {}).get("kernel") or {}
        rows = [("source", "/proc/kcore (live)" if km.kcore else "physical RAM image"),
                ("banner", meta.get("banner") or self._banner(km)),
                ("phys_base", "0x%x" % km.phys_base if km.phys_base is not None else "n/a (kcore)"),
                ("page_offset_base", "0x%x" % km.page_offset_base),
                ("paging", "5-level" if km.l5 else "4-level"),
                ("BTF types", str(len(km.btf.types) - 1)),
                ("symbols", str(len(km.symbols)))]
        rows += [("note", n) for n in km.notes]
        return TreeGrid([("Property", str), ("Value", str)], ((0, r) for r in rows))

    @staticmethod
    def _banner(km):
        try:
            return km.read(km.sym("linux_banner"), 256).split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        except (InvalidAddressException, RequirementError):
            return "?"


class PsList(_HostPlugin):
    NAME = "host.pslist"
    DESCRIPTION = ("Lists the processes in host kernel memory, with their global PID and the PID inside their own "
                   "PID namespace (WSL distros and containers), and marks those holding a GPU device handle "
                   "(/dev/dxg on WSL2, /dev/nvidia* on Linux).")
    METHOD = ("Walks init_task.tasks (thread-group leaders) with BTF offsets (an unreadable link ends the walk with "
              "a 'walk error' row); NsPID is thread_pid->numbers[thread_pid->level].nr; for each task walks "
              "files->fdt->fd[] and compares every file's f_op with dxgk_fops / nvidia_fops.")
    ANALOG = "linux.pslist + linux.lsof"
    REQUIREMENTS = HOST_REQS + [Requirement("gpu_only", bool, False, "only processes with a GPU handle")]

    def run(self):
        km = self.km()
        fops = {v: k for k, v in km.symbols.items() if k in ("dxgk_fops", "nvidia_fops")}

        def rows():
            errors = []
            for t in dxg.walk_tasks(km, errors=errors):
                handles = []
                try:
                    for fd, _fva, f_op, _priv in dxg.task_files(km, t["files"]):
                        if f_op in fops:
                            handles.append("%d:%s" % (fd, "dxg" if fops[f_op] == "dxgk_fops" else "nvidia"))
                except InvalidAddressException:
                    handles.append("files unreadable")
                if self.opts["gpu_only"] and not [h for h in handles if ":" in h]:
                    continue
                nspid = dxg.task_nspid(km, t["va"])
                yield 0, (t["pid"], nspid if nspid is not None else na("?"), t["comm"], Address(t["va"]),
                          bool(t["mm"]), ", ".join(handles) or na(""))
            for e in errors:
                yield 0, (na(""), na(""), na("walk error"), Address(0), na(""), e)
        return TreeGrid([("PID", int), ("NsPID", int), ("Comm", str), ("task_struct", Address), ("UserSpace", bool),
                         ("GPU handles", str)], rows())


class DxgProcs(_HostPlugin):
    NAME = "wsl.dxgprocs"
    DESCRIPTION = ("Lists every process the WSL2 GPU driver (dxgkrnl) knows - including processes inside PID "
                   "namespaces/containers and processes that exited or were unlinked - with the adapters, "
                   "devices, contexts, hardware queues and allocations each created, cross-checked against the "
                   "task list and the /dev/dxg handles tasks hold.")
    METHOD = ("Walks dxgdrv.dxgglobal->plisthead (dxgprocess: pid, tgid, vpid, nspid) -> process_adapter_list -> "
              "device_list -> context/hwqueue/allocation/resource/pagingqueue/syncobject lists, and each "
              "process's hmgrtable handle table (counts by HMGRENTRY type, destroyed entries flagged). Joins "
              "dxgprocess.tgid with init_task.tasks and file->private_data of files whose f_op is dxgk_fops.")
    ANALOG = "linux.pslist / windows.malware.psxview (GPU paravirtualisation view)"
    REQUIREMENTS = HOST_REQS

    def run(self):
        km = self.km()
        view = dxg.dxg_cross_view(km)
        self._view = view

        def rows():
            for p in view["processes"]:
                attention = []
                if not p["task_present"]:
                    attention.append("no task with this tgid (exited or hidden)")
                elif not p["dxg_fds"]:
                    attention.append("no open /dev/dxg handle")
                pages = sum(a["num_pages"] for a in p["allocations"])
                adapters = "; ".join(sorted({a["description"] for a in p["adapters"]}))
                yield 0, (p["pid"], p["vpid"], p["pidns"] if p["pidns"] is not None else na("?"),
                          p["task_comm"] or na("no task"), Address(p["va"]), adapters or na("none"),
                          p["devices"], p["contexts"], p["hwqueues"], len(p["allocations"]), pages * 4096,
                          ", ".join("%s=%d" % kv for kv in sorted(p["handles"].items())) or na(""),
                          ", ".join("fd %d (%s pid %d)" % (fd, comm, pid) for pid, comm, fd in p["dxg_fds"])
                          or na("none"), "; ".join(attention) or na(""))
            for u in view["unlinked_handles"]:
                holders = ", ".join("fd %d (%s pid %d)" % (fd, comm, pid) for pid, comm, fd in u["holders"])
                yield 0, (na(""), na(""), na(""), na("unlinked"), Address(u["dxgprocess"]), na(""), 0, 0, 0, 0, 0,
                          na(""), holders, "dxgprocess not on dxgglobal.plisthead (unlinked)")
            for e in view["errors"]:
                yield 0, (na(""), na(""), na(""), na(""), Address(0), na(""), 0, 0, 0, 0, 0, na(""), na(""),
                          "walk error: %s" % e)
        return TreeGrid([("PID", int), ("NsPID", int), ("PidNS", int), ("Comm", str), ("dxgprocess", Address),
                         ("Adapters", str), ("Devices", int), ("Contexts", int), ("HwQueues", int),
                         ("Allocations", int), ("AllocBytes", int), ("Handles", str), ("/dev/dxg", str),
                         ("Attention", str)], rows())


class DxgAllocs(_HostPlugin):
    NAME = "wsl.dxgallocs"
    DESCRIPTION = ("Lists the GPU allocations each WSL2 process created through dxgkrnl and, for allocations "
                   "backed by guest pages, reads those pages: dumps them and scans them for GPU code and "
                   "command artefacts (fatbins, cubins, PTX, pushbuffers, QMDs).")
    METHOD = ("dxgallocation {alloc_handle, num_pages, cpu_address, pages}: pages[] holds struct page pointers; "
              "pfn = (page - vmemmap_base) / sizeof(struct page). Pages are read from the image (or /proc/kcore) "
              "and swept with the same artefact scanners as VRAM and process dumps.")
    ANALOG = "linux.proc.Maps --dump (GPU-shared guest memory)"
    REQUIREMENTS = HOST_REQS + [
        Requirement("pid", int, None, "only this PID (global or namespace PID)"),
        Requirement("dump", bool, False, "write each guest-page-backed allocation to --output-dir"),
        Requirement("scan", bool, True, "sweep guest-page-backed allocations for GPU artefacts"),
        Requirement("max_pages", int, 65536, "skip allocations larger than this many pages")]

    def run(self):
        km = self.km()
        walk = dxg.walk_processes(km)
        out_dir = self.ctx.output_dir
        if self.opts["dump"] and not out_dir:
            raise RequirementError("--dump needs -o/--output-dir")

        def rows():
            for p in walk["processes"]:
                if self.opts["pid"] is not None and self.opts["pid"] not in (p["pid"], p["vpid"]):
                    continue
                for a in p["allocations"]:
                    content, found, note = None, [], ""
                    if a["pages"] and 0 < a["num_pages"] <= self.opts["max_pages"]:
                        try:
                            ptrs = km.read(a["pages"], a["num_pages"] * 8)
                            buf = bytearray()
                            for i in range(a["num_pages"]):
                                pg = int.from_bytes(ptrs[i * 8:i * 8 + 8], "little")
                                buf += km.read_phys(km.page_to_pa(pg), 4096) if pg else bytes(4096)
                            content = bytes(buf)
                        except (InvalidAddressException, RequirementError) as exc:
                            note = "pages unreadable: %s" % exc
                    elif a["pages"]:
                        note = "larger than --max-pages"
                    else:
                        note = "no guest pages (host/VRAM-backed)"
                    if content is not None:
                        if self.opts["scan"]:
                            found = ["%s@+0x%x %s" % (x.kind, x.offset, x.summary)
                                     for x in artifacts.sweep(BytesLayer("alloc", content), self.ctx.classdb)]
                        if self.opts["dump"]:
                            os.makedirs(out_dir, exist_ok=True)
                            path = os.path.join(out_dir, "dxgalloc-pid%d-%x.bin" % (p["pid"], a["handle"]))
                            with open(path, "wb") as fh:
                                fh.write(content)
                            note = (note + "; " if note else "") + "dumped to " + path
                        if not any(content):
                            note = (note + "; " if note else "") + "all zero"
                    yield 0, (p["pid"], p["vpid"], Address(a["va"]), "0x%08x" % a["handle"], a["num_pages"] * 4096,
                              Address(a["cpu_address"]) if a["cpu_address"] else na(""), a["cpu_mapped"],
                              a["resource_owner"], "; ".join(found) or na(""), note or na(""))
        return TreeGrid([("PID", int), ("NsPID", int), ("dxgallocation", Address), ("Handle", str), ("Bytes", int),
                         ("CPU VA", Address), ("CPUMapped", bool), ("ResourceOwned", bool), ("Artefacts", str),
                         ("Notes", str)], rows())


class DxgPageOwners(_HostPlugin):
    NAME = "wsl.dxgpageowners"
    DESCRIPTION = ("Checks who owns the guest pages behind each WSL2 GPU allocation: they should be mapped by the "
                   "process that created the allocation (at its CPU address). Pages also mapped by other processes, "
                   "kernel-image pages, or pages no process maps are flagged: the GPU can read and write them.")
    METHOD = ("dxgallocation.pages[] -> physical pages (vmemmap); every task's user page tables (mm->pgd, 4/5-level, "
              "huge pages) are walked to build the reverse map page -> (pid, comm, va, writable); kernel-image pages "
              "come from _text.._end (phys_base from the image, or the kernel-text segment with --kcore). A broken "
              "task list gives a 'walk error' row: mappings of the tasks after it are not counted.")
    ANALOG = "linux.proc.Maps + linux.pagecache (page ownership)"
    REQUIREMENTS = HOST_REQS + [Requirement("pid", int, None, "only this PID (global or namespace PID)"),
                                Requirement("max_pages", int, 1 << 20, "skip allocations larger than this many pages")]

    def run(self):
        from keto.hostmem import pageowners
        km = self.km()
        walk = dxg.dxg_cross_view(km)  # includes each process's task name
        work = []
        for p in walk["processes"]:
            if self.opts["pid"] is not None and self.opts["pid"] not in (p["pid"], p["vpid"]):
                continue
            for a in p["allocations"]:
                if not a["pages"] or not 0 < a["num_pages"] <= self.opts["max_pages"]:
                    continue
                try:
                    ptrs = km.read(a["pages"], a["num_pages"] * 8)
                except InvalidAddressException:
                    continue
                pas = [km.page_to_pa(int.from_bytes(ptrs[i * 8:i * 8 + 8], "little")) for i in range(a["num_pages"])
                       if int.from_bytes(ptrs[i * 8:i * 8 + 8], "little")]
                work.append((p, a, pas))
        errors = []
        owners = pageowners.owners(km, [pa for _p, _a, pas in work for pa in pas], errors)

        def rows():
            for p, a, pas in work:
                own_self = foreign = unmapped = kimage = 0
                foreign_names = set()
                base = a["cpu_address"] & ~0xFFF if a["cpu_address"] else None
                at_cpu = 0
                rng = pageowners.kernel_image_range(km)
                for i, pa in enumerate(pas):
                    os_ = owners.get(pa, [])
                    mine = [o for o in os_ if o.pid == p["tgid"]]
                    if mine:
                        own_self += 1
                        if base is not None and any(o.va == base + i * 0x1000 for o in mine):
                            at_cpu += 1
                    others = [o for o in os_ if o.pid != p["tgid"]]
                    if others:
                        foreign += 1
                        foreign_names.update("%s(%d)" % (o.comm, o.pid) for o in others)
                    if not os_:
                        if rng and rng[0] <= pa < rng[1]:
                            kimage += 1
                        else:
                            unmapped += 1
                att = []
                if foreign:
                    att.append("%d page(s) also mapped by %s" % (foreign, ", ".join(sorted(foreign_names))))
                if kimage:
                    att.append("%d KERNEL IMAGE page(s) reachable by the GPU" % kimage)
                sev = "high" if (foreign or kimage) else "info"
                yield 0, (p["pid"], p["vpid"], p.get("task_comm") or na("?"), "0x%08x" % a["handle"], len(pas),
                          own_self, at_cpu, foreign, unmapped, kimage, sev, "; ".join(att) or na(""))
            for e in errors:  # tasks after a broken link are missing: their mappings are not counted
                yield 0, (na(""), na(""), na("walk error"), na(""), 0, 0, 0, 0, 0, 0, na(""),
                          e + " (mappings of the tasks not reached are not counted)")
        return TreeGrid([("PID", int), ("NsPID", int), ("Comm", str), ("Allocation", str), ("Pages", int),
                         ("MappedByOwner", int), ("AtCpuAddress", int), ("Foreign", int), ("NotMapped", int),
                         ("KernelImage", int), ("Severity", str), ("Attention", str)], rows())
