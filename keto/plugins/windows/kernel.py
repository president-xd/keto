"""Windows kernel memory images (raw RAM, crash / live dumps, hibernation files, VM snapshots): processes,
modules, handles, VADs, drivers and the GPU view, typed through the imaged kernel's own PDB."""

from __future__ import annotations

import time
from typing import List

from keto import __version__
from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import Address, TreeGrid, na
from keto.live.gpuhandles import handle_kind
from keto.plugins.nvidia.envscan import VARIABLES as GPU_ENV, severity as env_severity
from keto.plugins.windows.gpu import USER_WRITABLE, runtimes
from keto.winmem import objects
from keto.winmem.paging import PAGE
from keto.winmem.session import WIN_REQS, looks_windows, win_kernel
from keto.winmem.symtab import SymbolError

GPU_ENV_NAMES = {n for n, _s, _w in GPU_ENV}
PID_REQ = Requirement("pid", int, None, "only this process id", multiple=True)


def _t(dt) -> object:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else na("")


def _basename(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]


class _WinPlugin(Plugin):
    SOURCES = ("file",)
    CATEGORY = "windows"
    REQUIREMENTS = WIN_REQS

    def kernel(self):
        return win_kernel(self.ctx, self.opts)

    def selected(self, k):
        pids = self.opts.get("pid") or []
        procs = objects.processes(k)
        if pids:
            procs = [p for p in procs if p.get("UniqueProcessId") in pids]
            if not procs:
                raise RequirementError("no process with pid %s in the active process list" % ", ".join(map(str, pids)))
        return procs


class KernelInfo(_WinPlugin):
    NAME = "windows.kernel.info"
    DESCRIPTION = ("Identifies the imaged Windows kernel and how its memory is read: image format, dump header "
                   "facts, directory table base, kernel base, PDB identity and symbol source, build and paging "
                   "mode.")
    METHOD = ("The DTB comes from --dtb, the image header (crash dump DirectoryTableBase, a recorded CPU CR3), the "
              "x64 low stub (_PROCESSOR_START_BLOCK in the first MiB) or a self-referencing PML4 page, accepted "
              "only when it maps KUSER_SHARED_DATA with NtMajorVersion 10. The kernel base is the page whose PE "
              "CodeView record names ntkrnlmp.pdb (found through PsLoadedModuleList, below a kernel address, or by "
              "scanning the kernel image range); that record's GUID/age selects the PDB from the local symbol "
              "stores.")
    ANALOG = "windows.info"

    def run(self):
        k = self.kernel()
        meta = k.image_meta
        rows = [("image format", meta.get("format", "?")), ("layer", k.layer_name),
                ("DTB", "0x%x" % k.dtb), ("paging", "%d-level" % k.levels), ("kernel base", "0x%x" % k.base),
                ("kernel PDB", "%s %s" % (k.codeview.pdb_name, k.codeview.key)),
                ("symbols", k.symtab.source), ("build", str(getattr(k, "build", None) or "?"))]
        try:
            rows.append(("NtBuildLab", k.read(k.sym("NtBuildLab"), 128).split(b"\x00", 1)[0].decode("ascii", "replace")))
        except (InvalidAddressException, RequirementError):
            pass
        try:  # exported as a CCHAR: one byte
            rows.append(("processors", str(k.u8(k.sym("KeNumberProcessors")))))
        except (InvalidAddressException, RequirementError):
            pass
        for key in ("dump_type", "bugcheck_code", "system_time", "number_processors", "comment"):
            if meta.get(key) not in (None, ""):
                v = meta[key]
                rows.append((key.replace("_", " "), "0x%x" % v if key == "bugcheck_code" and isinstance(v, int) else str(v)))
        rows += [("note", n) for n in k.notes]
        return TreeGrid([("Property", str), ("Value", str)], ((0, r) for r in rows))


class PsList(_WinPlugin, TimeLinerInterface):
    NAME = "windows.kernel.pslist"
    DESCRIPTION = ("Lists the processes on the kernel's active process list with parent, threads, session, WoW64, "
                   "create/exit times, image path, and whether each has a graphics-kernel (DxgKrnl) process object.")
    METHOD = ("Walks nt!PsActiveProcessHead through _EPROCESS.ActiveProcessLinks with PDB offsets; the full image "
              "path is SeAuditProcessCreationInfo.ImageFileName; DxgProcess is _EPROCESS.DxgProcess (non-null once "
              "the process used D3DKMT / the GPU). A broken link ends the walk with a note in windows.kernel.info.")
    ANALOG = "windows.pslist"
    REQUIREMENTS = WIN_REQS + [PID_REQ]

    def run(self):
        k = self.kernel()

        def rows():
            for ep in self.selected(k):
                i = objects.proc_info(k, ep)
                yield 0, (i["pid"], i["ppid"], i["name"], Address(i["va"]), i["threads"] if i["threads"] is not None
                          else na("?"), i["session"] if i["session"] is not None else na(""), i["wow64"],
                          _t(i["create_time"]), _t(i["exit_time"]),
                          Address(i["dxg_process"]) if i["dxg_process"] else na(""), i["path"] or na(""))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("Offset(V)", Address), ("Threads", int),
                         ("Session", int), ("Wow64", bool), ("CreateTime", str), ("ExitTime", str),
                         ("DxgProcess", Address), ("Path", str)], rows())

    def generate_timeline(self):
        if not looks_windows(self.ctx):
            raise RequirementError("not a Windows kernel memory image")
        k = self.kernel()
        for ep in objects.processes(k):
            i = objects.proc_info(k, ep)
            label = "Windows process %s (%s)%s" % (i["name"], i["pid"], " [GPU: DxgKrnl]" if i["dxg_process"] else "")
            if i["create_time"]:
                yield label + " created", "Created", i["create_time"]
            if i["exit_time"]:
                yield label + " exited", "Exited", i["exit_time"]


class PsScan(_WinPlugin):
    NAME = "windows.kernel.psscan"
    DESCRIPTION = ("Finds _EPROCESS objects by pool tag in physical memory, including exited processes and "
                   "processes unlinked from the active list (a rootkit's way to hide a GPU miner), and marks each "
                   "as listed or not.")
    METHOD = ("Scans for the 'Proc' pool tag; a hit counts when its allocation holds a _KPROCESS dispatcher header "
              "(Type 3, Size = sizeof(_KPROCESS)/4). The kernel address is recovered through ActiveProcessLinks "
              "and confirmed by translating it back; the result is compared with the PsActiveProcessHead walk. "
              "Without a kernel address, members are read from the body's physical page only (partial).")
    ANALOG = "windows.psscan"

    def run(self):
        k = self.kernel()
        listed = {ep.va for ep in objects.processes(k)}
        known = {}
        for va in listed:
            try:
                known[k.v2p(va)] = va
            except InvalidAddressException:
                pass
        found = objects.pool_scan_processes(k, known)

        def rows():
            for i in sorted(found, key=lambda d: (d.get("pid") or 0, d["phys"])):
                in_list = i["va"] in listed if i["va"] is not None else None
                if in_list:
                    note = ""
                elif i.get("exit_time"):
                    note = "exited"
                elif i["va"] is None:
                    note = "kernel address not recovered (partial)"
                else:
                    note = "NOT on the active process list: unlinked (hidden?)"
                yield 0, (i.get("pid") if i.get("pid") is not None else na("?"),
                          i.get("ppid") if i.get("ppid") is not None else na("?"), i.get("name") or na("?"),
                          Address(i["phys"]), Address(i["va"]) if i["va"] is not None else na("?"),
                          _t(i.get("create_time")), _t(i.get("exit_time")),
                          in_list if in_list is not None else na("?"), note or na(""))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("Offset(P)", Address), ("Offset(V)", Address),
                         ("CreateTime", str), ("ExitTime", str), ("Listed", bool), ("Note", str)], rows())


class Modules(_WinPlugin):
    NAME = "windows.kernel.modules"
    DESCRIPTION = ("Lists loaded kernel modules (drivers) with base, size, path and PDB identity, and marks the "
                   "GPU stack: the NVIDIA kernel driver, DirectX graphics kernel and scheduler, and display filters.")
    METHOD = ("Walks nt!PsLoadedModuleList (_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks); the PDB name and GUID come "
              "from each image's in-memory PE CodeView record when its header page is resident.")
    ANALOG = "windows.modules"

    GPU = {"nvlddmkm.sys": "NVIDIA kernel-mode driver", "dxgkrnl.sys": "DirectX graphics kernel",
           "dxgmms2.sys": "DirectX graphics memory manager / scheduler", "dxgmms1.sys": "DirectX graphics MM (v1)",
           "nvvad64v.sys": "NVIDIA virtual audio", "nvhda64v.sys": "NVIDIA HD audio", "nvvhci.sys": "NVIDIA VHCI",
           "basicdisplay.sys": "Microsoft basic display", "basicrender.sys": "Microsoft basic render"}

    def run(self):
        from keto.winmem import pe
        k = self.kernel()

        def rows():
            for m in objects.modules(k):
                cv = pe.safe_codeview(k.read, m["base"]) if m["base"] else None
                if cv:
                    pdb = "%s %s" % (cv.pdb_name, cv.key)
                else:
                    pdb = na("no CodeView record" if m["base"] and k.readable(m["base"]) else "header not resident")
                gpu = self.GPU.get(m["name"].lower(), "")
                yield 0, (Address(m["base"]), m["size"], m["name"] or na("?"), m["path"] or na(""), pdb, gpu or na(""))
        return TreeGrid([("Base", Address), ("Size", int), ("Name", str), ("Path", str), ("PDB", str),
                         ("GPU stack", str)], rows())


class Handles(_WinPlugin):
    NAME = "windows.kernel.handles"
    DESCRIPTION = ("Lists the open handles of processes with object type, granted access and name, and marks "
                   "handles to GPU devices and GPU driver files (DxgKrnl, NVIDIA control devices, the CUDA kernel "
                   "archive, shader and JIT caches).")
    METHOD = ("Walks _EPROCESS.ObjectTable -> _HANDLE_TABLE.TableCode (0-2 levels); each entry's object header "
              "comes from ObjectPointerBits; the type index is decoded with nt!ObHeaderCookie and the header "
              "address and looked up in nt!ObTypeIndexTable; names come from _OBJECT_HEADER_NAME_INFO (located "
              "with nt!ObpInfoMaskToOffset) and, for files, the device object's name plus _FILE_OBJECT.FileName.")
    ANALOG = "windows.handles"
    REQUIREMENTS = WIN_REQS + [PID_REQ, Requirement("gpu_only", bool, False, "only GPU-related handles")]

    def run(self):
        k = self.kernel()
        oi = objects.ObjectInfo(k)
        gpu_only = self.opts.get("gpu_only")

        def rows():
            errors: List[str] = []
            for ep in self.selected(k):
                pid, name = ep.get("UniqueProcessId"), ep.string("ImageFileName")
                for h in objects.handles(k, ep, oi, errors):
                    kind = handle_kind(h["name"]) if h["name"] else None
                    if gpu_only and not kind:
                        continue
                    yield 0, (pid, name, h["handle"], h["type"], "0x%x" % h["access"], h["name"] or na(""),
                              Address(h["object"]), kind or na(""))
            for e in errors:
                yield 0, (na(""), na("walk error"), na(""), na(""), na(""), e, Address(0), na(""))
        return TreeGrid([("PID", int), ("Process", str), ("Handle", int), ("Type", str), ("Access", str),
                         ("Name", str), ("Object", Address), ("GPU", str)], rows())


class VadInfo(_WinPlugin):
    NAME = "windows.kernel.vadinfo"
    DESCRIPTION = "Lists the virtual address descriptors (VADs) of processes: range, protection, private or mapped, " \
                  "and the mapped file."
    METHOD = ("Walks _EPROCESS.VadRoot (_RTL_AVL_TREE of _MMVAD_SHORT); start/end from StartingVpn[High] / "
              "EndingVpn[High]; protection and private flags from _MMVAD_FLAGS; mapped files from "
              "_MMVAD.Subsection -> ControlArea -> FilePointer (_EX_FAST_REF) -> _FILE_OBJECT.FileName.")
    ANALOG = "windows.vadinfo"
    REQUIREMENTS = WIN_REQS + [PID_REQ]

    def run(self):
        k = self.kernel()

        def rows():
            errors: List[str] = []
            for ep in self.selected(k):
                pid = ep.get("UniqueProcessId")
                for v in objects.vads(k, ep, errors):
                    yield 0, (pid, ep.string("ImageFileName"), Address(v["start"]), Address(v["end"]),
                              objects.vad_protection(v["protection"]), v["private"], v["file"] or na(""))
            for e in errors:
                yield 0, (na(""), na("walk error"), Address(0), Address(0), na(""), False, e)
        return TreeGrid([("PID", int), ("Process", str), ("Start", Address), ("End", Address), ("Protection", str),
                         ("Private", bool), ("File", str)], rows())


class Envars(_WinPlugin):
    NAME = "windows.kernel.envars"
    DESCRIPTION = ("Reads each process's environment block from its user memory and reports the GPU, CUDA "
                   "injection and loader variables with the same severity rules as nvidia.envscan.")
    METHOD = ("_EPROCESS.Peb -> _PEB.ProcessParameters -> _RTL_USER_PROCESS_PARAMETERS.Environment (UTF-16 "
              "NAME=VALUE strings, EnvironmentSize bytes), read through the process's DirectoryTableBase; pages "
              "that are paged out are reported, not guessed.")
    ANALOG = "windows.envars"
    REQUIREMENTS = WIN_REQS + [PID_REQ, Requirement("all", bool, False, "every variable, not only GPU-relevant ones")]

    def run(self):
        k = self.kernel()
        show_all = self.opts.get("all")

        def rows():
            for ep in self.selected(k):
                pid, name = ep.get("UniqueProcessId"), ep.string("ImageFileName")
                try:
                    env = _environment(k, ep)
                except (InvalidAddressException, SymbolError) as e:
                    yield 0, (pid, name, na("unreadable"), str(e), na(""))
                    continue
                for var, value in env:
                    upper = var.upper()
                    if upper in GPU_ENV_NAMES:
                        yield 0, (pid, name, var, value, env_severity(upper, value))
                    elif show_all:
                        yield 0, (pid, name, var, value, na(""))
        return TreeGrid([("PID", int), ("Process", str), ("Variable", str), ("Value", str), ("Severity", str)], rows())


def _environment(k, ep):
    dtb = objects.process_space_dtb(ep)
    peb = ep.get("Peb")
    if not peb:
        return []

    def need(value, what, va):
        if value is None:  # WinObj.get gives None for a member it cannot read
            raise InvalidAddressException("user", va, "%s not in the image (user-mode pages not acquired? "
                                                      "acquire --method livedump --include-user-pages)" % what)
        return value

    p = k.obj("_PEB", peb, dtb)
    need(p.get("ProcessParameters"), "PEB", peb)
    params = p.deref("ProcessParameters", "_RTL_USER_PROCESS_PARAMETERS")
    if params is None:
        return []
    env_va = need(params.get("Environment"), "process parameters", params.va)
    size = params.get("EnvironmentSize") or 0x8000
    data = k.read(env_va, min(size, 0x40000), dtb)
    out = []
    for item in data.decode("utf-16-le", "replace").split("\x00"):
        if not item:
            break
        sep = item.find("=", 1)  # a name may start with '=' (per-drive current directories such as =C:)
        if sep > 0:
            out.append((item[:sep], item[sep + 1:]))
    return out


#: Microsoft framework / port / class drivers that own their client drivers' dispatch tables by design (the client
#: calls the framework's initialisation, which fills MajorFunction with the framework's own dispatchers)
FRAMEWORKS = {"wdf01000.sys": "KMDF", "ndis.sys": "NDIS", "ks.sys": "kernel streaming", "portcls.sys": "audio port",
              "storport.sys": "storage port", "classpnp.sys": "storage class", "hidclass.sys": "HID class",
              "rdbss.sys": "redirector", "mrxsmb.sys": "SMB redirector", "dxgkrnl.sys": "display miniport (DirectX)",
              "videoprt.sys": "video port", "lxcore.sys": "WSL", "ataport.sys": "ATA port", "scsiport.sys": "SCSI port",
              "usbport.sys": "USB port", "wudfrd.sys": "UMDF reflector"}


def _framework(m) -> str:
    if not m:
        return ""
    if "\\system32\\drivers\\" not in (m["path"] or "").lower():
        return ""  # the name alone is not enough: the framework image lives in system32\drivers
    return FRAMEWORKS.get((m["name"] or "").lower(), "")


class DriverIrp(_WinPlugin):
    NAME = "windows.kernel.driverirp"
    DESCRIPTION = ("Checks every driver object's IRP dispatch table (MajorFunction): an entry outside every loaded "
                   "module is reported as high (classic hook), one inside another driver as medium; dispatch by the "
                   "driver itself, ntoskrnl, or the Microsoft framework/port driver that owns it (KMDF, NDIS, "
                   "storport, display miniports through dxgkrnl, ...) is expected. GPU drivers are always listed.")
    METHOD = ("nt!ObpRootDirectoryObject -> \\Driver directory (37 hash buckets of _OBJECT_DIRECTORY_ENTRY) -> "
              "_DRIVER_OBJECT; each MajorFunction[0..27] target is resolved against PsLoadedModuleList. A framework "
              "counts only when it is the loaded image under \\SystemRoot\\system32\\drivers with a known name.")
    ANALOG = "windows.driverirp"
    REQUIREMENTS = WIN_REQS + [Requirement("all", bool, False, "list every dispatch entry of every driver")]
    GPU_DRIVERS = ("nvlddmkm", "dxgkrnl", "dxgmms2", "basicdisplay", "basicrender", "igfx", "amdkmdag")

    def run(self):
        k = self.kernel()
        mods = objects.modules(k)
        nt = mods[0] if mods else None
        show_all = self.opts.get("all")

        def rows():
            for d in objects.driver_objects(k):
                own = (d["start"], d["start"] + d["size"])
                gpu = any(g in d["name"].lower() for g in self.GPU_DRIVERS)
                for i, target in enumerate(d["major"]):
                    if not target:
                        continue
                    m = objects.module_at(mods, target)
                    if own[0] <= target < own[1]:
                        owner, finding = "driver itself", ""
                    elif nt is not None and m is nt:
                        owner, finding = "ntoskrnl", ""
                    elif _framework(m):
                        owner, finding = "framework: %s" % _framework(m), ""
                    elif m:
                        owner, finding = "another driver", "dispatch points into another driver (%s)" % m["name"]
                    else:
                        owner, finding = "no module", "dispatch outside every loaded module (unbacked code)"
                    if not (show_all or finding or gpu):
                        continue
                    yield 0, (d["name"], objects.IRP_MJ[i], Address(target), m["name"] if m else na("no module"),
                              owner, finding or na(""))
        return TreeGrid([("Driver", str), ("IRP", str), ("Target", Address), ("Module", str), ("Owner", str),
                         ("Finding", str)], rows())


class GpuProcs(_WinPlugin):
    NAME = "windows.kernel.gpuprocs"
    DESCRIPTION = ("Offline GPU process view of a Windows memory image: processes with a graphics-kernel process "
                   "object, GPU runtimes mapped (CUDA, NVRTC/PTX JIT, OpenCL, DirectML, Vulkan, D3D12, NVAPI) and "
                   "handles to GPU devices, flagging compute runtimes loaded from user-writable paths.")
    METHOD = ("Per process: _EPROCESS.DxgProcess; mapped image files from the VAD tree classified with the same "
              "runtime table as the live windows.gpuprocs; handles classified as in windows.kernel.handles. "
              "DxgProcess alone is common (any GUI process); CUDA/OpenCL runtimes or GPU device handles in a "
              "process without a window are what deserve a look.")
    ANALOG = "windows.pslist + windows.dlllist + windows.handles (GPU view)"
    REQUIREMENTS = WIN_REQS + [PID_REQ, Requirement("all", bool, False, "every process, not only GPU users"),
                               Requirement("hidden", bool, False, "also pool-scan physical memory for running "
                                                                  "processes unlinked from the active list (slower)")]

    def _hidden(self, k, listed):
        known = {}
        for ep in listed:
            try:
                known[k.v2p(ep.va)] = ep.va
            except InvalidAddressException:
                pass
        listed_va = {ep.va for ep in listed}
        for i in objects.pool_scan_processes(k, known):
            if i["va"] is not None and i["va"] not in listed_va and not i.get("exit_time"):
                yield k.obj("_EPROCESS", i["va"])

    def run(self):
        k = self.kernel()
        oi = objects.ObjectInfo(k)
        show_all = self.opts.get("all")

        def rows():
            listed = self.selected(k)
            hidden = list(self._hidden(k, listed)) if self.opts.get("hidden") else []
            for ep in listed + hidden:
                i = objects.proc_info(k, ep)
                files = [v["file"] for v in objects.vads(k, ep) if v["file"]]
                rts = runtimes([{"name": _basename(f).lower(), "path": f} for f in files])
                hk = sorted({handle_kind(h["name"]) for h in objects.handles(k, ep, oi) if h["name"]} - {None})
                flags = ["NOT on the active process list (unlinked, hidden?)"] if ep in hidden else []
                for label, compute, path in rts:
                    if compute and USER_WRITABLE.search(path or ""):
                        flags.append("%s from user-writable path %s" % (label, path))
                if not (show_all or i["dxg_process"] or rts or hk or ep in hidden):
                    continue
                yield 0, (i["pid"], i["ppid"], i["name"], Address(i["dxg_process"]) if i["dxg_process"] else na(""),
                          ", ".join(sorted({label for label, _c, _p in rts})) or na(""),
                          ", ".join(hk) or na(""), any(c for _l, c, _p in rts), "; ".join(flags) or na(""),
                          i["path"] or na(""))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("DxgProcess", Address), ("Runtimes", str),
                         ("GPU handles", str), ("Compute", bool), ("Findings", str), ("Path", str)], rows())


class ProcDump(_WinPlugin):
    NAME = "windows.kernel.procdump"
    DESCRIPTION = ("Writes the resident memory of a process from a Windows memory image into a .keto process "
                   "container (the layout of 'acquire --method process'), so nvidia.artifactscan, nvidia.envscan "
                   "and the other process-dump plugins run on it unchanged.")
    METHOD = ("For each VAD of the process, translates every page through the process's DirectoryTableBase "
              "(present and transition pages; prototype, paged-out and demand-zero pages are counted, not "
              "invented) and appends resident pages to the 'process' space keyed by virtual address; the VAD list "
              "with protections and mapped files becomes metadata.process.mappings. Needs -o.")
    ANALOG = "windows.memmap --dump / windows.pslist --dump"
    REQUIREMENTS = WIN_REQS + [Requirement("pid", int, None, "process id to dump (required)", multiple=True)]

    def run(self):
        from keto.formats.container import ContainerWriter
        k = self.kernel()
        if not self.opts.get("pid"):
            raise RequirementError("windows.kernel.procdump needs --pid")

        def rows():
            for ep in self.selected(k):
                i = objects.proc_info(k, ep)
                dtb = i["dtb"]
                path = self.ctx.output_path("pid%d_%s.keto" % (i["pid"], i["name"] or "process"))
                meta = {"tool": "Keto", "tool_version": __version__,
                        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
                        "acquisition": {"method": "windows.kernel.procdump", "status": "complete",
                                        "source_image": self.ctx.image_path or "--host-image"},
                        "process": {"pid": i["pid"], "comm": i["name"], "exe": i["path"], "ppid": i["ppid"],
                                    "platform": "Windows", "mappings": []}}
                writer = ContainerWriter(path, meta, exclusive=True)
                resident = missing = 0
                try:
                    for v in objects.vads(k, ep):
                        got = 0
                        for va in range(v["start"], v["end"] + 1, PAGE):
                            try:
                                writer.append("process", va, k.read(va, PAGE, dtb))
                                got += 1
                            except InvalidAddressException:
                                missing += 1
                        resident += got
                        meta["process"]["mappings"].append({
                            "start": v["start"], "end": v["end"] + 1, "perms": objects.vad_protection(v["protection"]),
                            "path": v["file"], "type": "private" if v["private"] else "mapped",
                            "resident_pages": got})
                finally:
                    meta["acquisition"]["notes"] = ("%d resident pages written, %d not resident (paged out, "
                                                    "prototype or never touched)" % (resident, missing))
                    writer.metadata = meta
                    writer.close()
                yield 0, (i["pid"], i["name"], resident, missing, path, writer.fingerprint)
        return TreeGrid([("PID", int), ("Process", str), ("Resident pages", int), ("Not resident", int),
                         ("File", str), ("Fingerprint", str)], rows())

