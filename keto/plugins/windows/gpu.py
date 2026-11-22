"""Windows: which processes use the GPU, through which runtime, and whether that fits what they are.

All in-the-wild GPU-evasion samples documented so far run on Windows: CoffeeLoader/ArmouryLoader decrypt
their payload with an OpenCL kernel, GPUGate gates execution on OpenCL being present, Cloak-and-Filter uses
the GPU for file-less execution, and GPU miners hide as background processes. The host-visible traces are
the GPU runtime DLLs a process loads and the per-process GPU engine and memory counters Windows keeps.
"""

from __future__ import annotations

import re
from typing import Dict

from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size
from keto.indicators import miners
from keto.live.source import NotRecordedError

RUNTIMES = [  # (regex on lower-case module name, runtime label, compute?)
    (r"^nvcuda(64)?\.dll$", "CUDA driver", True),
    (r"^cudart(32|64)_\d+\.dll$", "CUDA runtime", True),
    (r"^nvrtc(64|32)?_\d+.*\.dll$", "NVRTC (runtime compilation)", True),
    (r"^nvptxjitcompiler(32|64)?\.dll$", "PTX JIT compiler", True),
    (r"^nvjitlink.*\.dll$", "nvJitLink", True),
    (r"^opencl\.dll$", "OpenCL ICD loader", True),
    (r"^nvopencl(32|64)?\.dll$", "NVIDIA OpenCL driver", True),
    (r"^directml\.dll$", "DirectML", True),
    (r"^vulkan-1\.dll$", "Vulkan loader", False),
    (r"^nvoglv(32|64)\.dll$", "NVIDIA OpenGL/Vulkan driver", False),
    (r"^d3d12\.dll$", "Direct3D 12", False),
    (r"^nvapi(64)?\.dll$", "NVAPI", False),
]
_RT = [(re.compile(rx), label, compute) for rx, label, compute in RUNTIMES]
USER_WRITABLE = re.compile(r"\\(?:appdata\\(?:local|roaming|locallow)|temp|tmp|downloads|users\\public|programdata"
                           r"|windows\\temp|desktop)\\", re.I)
SYSTEM_GPU_USERS = {"system", "dwm.exe", "csrss.exe", "explorer.exe", "searchhost.exe", "startmenuexperiencehost.exe",
                    "textinputhost.exe", "shellexperiencehost.exe", "applicationframehost.exe", "lockapp.exe",
                    "nvcontainer.exe", "nvdisplay.container.exe", "nvidia overlay.exe", "nvidia app.exe",
                    "widgets.exe", "crossdeviceresume.exe", "phoneexperiencehost.exe", "audiodg.exe"}


#: shells and terminal hosts: a console program started from an interactive terminal shows in that terminal's
#: window (owned by WindowsTerminal.exe, conhost.exe, mintty.exe or an IDE), not in a window of its own
CONSOLE_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "openconsole.exe", "conhost.exe",
                 "wt.exe", "bash.exe"}
#: launchers whose window is never inherited by what they start
NO_INHERIT = {"explorer.exe", "services.exe", "svchost.exe", "wininit.exe", "winlogon.exe", "taskhostw.exe",
              "sihost.exe", "userinit.exe", "runtimebroker.exe", "wmiprvse.exe"}
NOT_RECORDED = "not recorded in snapshot"


def runtimes(mods):
    out = []
    for m in mods or []:
        n = (m.get("name") or "").lower()
        for rx, label, compute in _RT:
            if rx.match(n):
                out.append((label, compute, m.get("path") or n))
    return out


def basename(path: str) -> str:
    return re.split(r"[\\/]", path or "")[-1]


def system_root(src) -> str:
    return ((src.platform() or {}).get("system_root") or r"C:\Windows").rstrip("\\")


def win_path(src, text: str) -> str:
    """A Win32 file path from a registry ImagePath, driver path or command line: quotes and arguments removed,
    ``\\SystemRoot\\``, ``%SystemRoot%``, ``\\??\\`` and bare ``System32\\`` prefixes resolved."""
    t = (text or "").strip()
    m = re.match(r'^"([^"]+)"', t) or re.match(r"^(.+?\.(?:exe|sys|dll|json))(?=\s|$)", t, re.I)
    if m:
        t = m.group(1)
    root, low = system_root(src), t.lower()
    if low.startswith("\\systemroot\\"):
        t = root + t[len("\\SystemRoot"):]
    elif low.startswith("%systemroot%\\"):
        t = root + t[len("%SystemRoot%"):]
    elif low.startswith(("\\??\\", "\\\\?\\")):
        t = t[4:]
    elif low.startswith("system32\\"):
        t = root + "\\" + t
    return t


def has_window(p, by_pid, own_window) -> bool:
    """Own visible window, or one owned by an ancestor the process runs inside: a same-image ancestor (browser/
    Electron GPU and renderer processes) or the interactive shell / terminal that started a console program.
    A window of explorer.exe or another launcher is never inherited, and a "parent" that started after the child
    holds a reused PID and ends the walk."""
    seen = set()
    while p and p["pid"] not in seen:
        if p["pid"] in own_window:
            return True
        seen.add(p["pid"])
        parent = by_pid.get(p.get("ppid"))
        if not parent:
            return False
        cur, par = (p.get("name") or "").lower(), (parent.get("name") or "").lower()
        if par in NO_INHERIT:
            return False
        if p.get("start_time") and parent.get("start_time") and parent["start_time"] > p["start_time"]:
            return False
        p = parent if par == cur or par in CONSOLE_HOSTS or cur in CONSOLE_HOSTS else None
    return False


def win_gpu_processes(src, modules=None) -> Dict[int, dict]:
    """Windows counterpart of ``procfs.gpu_processes``: every process in an NVML process list, with a Windows GPU
    counter instance (engine time or GPU memory) or with a GPU runtime DLL loaded.
    ``pid -> {proc, evidence, modules}``; NVML PIDs absent from the process list have ``proc`` None. The Keto
    process itself is left out (it loads NVML/CUDA to answer the query). ``modules`` is an optional
    ``pid -> module list`` map already collected."""
    from keto.live import procfs
    nv = procfs.nvml_pids(src.nvml())
    counters = src.win_gpu().get("processes") or {}
    self_pid = (src.platform() or {}).get("self_pid")
    out: Dict[int, dict] = {}
    for p in src.win_processes():
        pid = p["pid"]
        if pid == self_pid:
            continue
        mods = modules[pid] if modules is not None and pid in modules else src.win_modules(pid)
        ev = set(nv.get(pid, ()))
        if str(pid) in counters:
            ev.add("gpu-counters")
        ev.update("dll:" + basename(path).lower() for _label, _compute, path in runtimes(mods))
        if ev:
            out[pid] = {"proc": p, "evidence": ev, "modules": mods}
    for pid, labels in nv.items():
        if pid not in out and pid != self_pid:
            out[pid] = {"proc": None, "evidence": set(labels) | {"not-in-process-list"}, "modules": None}
    return out


class GpuProcs(Plugin):
    NAME = "windows.gpuprocs"
    CATEGORY = "windows"
    DESCRIPTION = ("Lists every Windows process that uses the GPU or loads a GPU runtime (CUDA, NVRTC/PTX JIT, "
                   "OpenCL, DirectML, Vulkan, D3D12, NVAPI) with its GPU engine utilisation and GPU memory, and "
                   "flags GPU compute in windowless processes, GPU runtimes loaded from user-writable paths "
                   "(loader/dropper locations) and miner-like names.")
    METHOD = ("Toolhelp32 process and module snapshots plus QueryFullProcessImageNameW; command lines from each "
              "process's PEB (NtQueryInformationProcess + ReadProcessMemory); Authenticode status of the image and "
              "GPU runtime DLLs (WinVerifyTrust, embedded then system catalogs, no network); adapter names from "
              "DXGI EnumAdapters1 matched by LUID; EnumWindows for visible windows (inherited from a same-image "
              "parent or from the interactive shell/terminal that started a console program); PDH "
              "'\\GPU Engine(*)\\Utilization Percentage' (two samples) and '\\GPU Process Memory(*)\\"
              "Dedicated/Shared Usage', whose instance names carry the PID, adapter LUID and engine type. GPU "
              "runtime DLLs under AppData, Temp, Downloads, Public, ProgramData or Desktop (outside the image's own "
              "folder) are flagged with their path. The Keto process itself is not listed.")
    ANALOG = "windows.pslist + windows.dlllist (GPU view)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("all", bool, False, "list every process, not only GPU users"),
                    Requirement("busy", float, 5.0, "engine utilisation % (0-100) at or above which an engine "
                                                     "counts as active GPU work; 0 means any non-zero utilisation"),
                    Requirement("no_signatures", bool, False, "skip Authenticode checks (faster)")]

    def run(self):
        src = self.ctx.live
        if (src.platform() or {}).get("system") != "Windows":
            raise UnsupportedError("windows.gpuprocs needs a live (or snapshotted) Windows system")
        busy = self.opts["busy"]
        if not 0 <= busy <= 100:
            raise RequirementError("--busy must be a utilisation percentage between 0 and 100 (got %s)" % busy)
        procs = src.win_processes()
        by_pid = {p["pid"]: p for p in procs}
        own_window = set(src.win_windowed())
        gpu = src.win_gpu()
        counters = gpu.get("processes", {})
        self_pid = (src.platform() or {}).get("self_pid")
        adapter_names = {}
        for a in src.win_adapters() or []:
            adapter_names[a["luid"]] = a["name"]

        def adapter_label(luid):
            try:
                from keto.live.windows import normalise_luid
                luid = normalise_luid(luid)
            except (ValueError, ImportError):
                pass
            return adapter_names.get(luid, luid)

        def recorded(fn, *args):
            """A query result, or the NOT_RECORDED marker when a snapshot replay lacks it (e.g. with --all)."""
            try:
                return fn(*args)
            except NotRecordedError:
                return NOT_RECORDED

        def sig(path):
            if self.opts["no_signatures"] or not path:
                return None
            s = recorded(src.win_signature, path)
            return None if s == NOT_RECORDED else s

        def rows():
            for p in sorted(procs, key=lambda x: x["pid"]):
                pid = p["pid"]
                if pid == self_pid:
                    continue  # Keto itself loads NVML/CUDA to answer the query
                mods = src.win_modules(pid)
                rts = runtimes(mods)
                g = counters.get(str(pid)) or {}
                active = {e: u for e, u in (g.get("engines") or {}).items() if u > 0 and u >= busy}
                if not (rts or active or g) and not self.opts["all"]:
                    continue
                name = p.get("name") or "?"
                path = p.get("path") or ""
                windowed = {pid} if has_window(p, by_pid, own_window) else set()
                compute_rt = [r for r in rts if r[1]]
                reasons = []
                if name.lower() == "vmwp.exe" and g:
                    reasons.append("note: Hyper-V worker - GPU work of WSL2/VM guests (analyse inside the guest "
                                   "with wsl.dxgprocs)")
                if compute_rt and pid not in windowed and name.lower() not in SYSTEM_GPU_USERS:
                    reasons.append("GPU compute runtime (%s) in a process without a visible window"
                                   % ", ".join(sorted({r[0] for r in compute_rt})))
                if compute_rt and path and USER_WRITABLE.search(path):
                    reasons.append("GPU compute runtime loaded by an image in a user-writable location")
                image_dir = path.rsplit("\\", 1)[0].lower() + "\\" if "\\" in path else None
                for label, _compute, mpath in rts:
                    if "\\" in mpath and USER_WRITABLE.search(mpath) and \
                            not (image_dir and mpath.lower().startswith(image_dir)):
                        reasons.append("GPU runtime %s loaded from a user-writable location: %s" % (label, mpath))
                if active and pid not in windowed and name.lower() not in SYSTEM_GPU_USERS:
                    reasons.append("GPU engines busy without a visible window (%s)"
                                   % ", ".join("%s %.0f%%" % kv for kv in sorted(active.items())))
                cmd = recorded(src.win_cmdline, pid)
                for where, text in (("process name", name.rsplit(".", 1)[0]), ("image path", path),
                                    ("command line", cmd if isinstance(cmd, str) and cmd != NOT_RECORDED else "")):
                    for cat, ind in miners.classify(text, context="process"):
                        reasons.append("%s indicator in %s (%s)" % (cat, where, ind))
                isig = sig(path) if (compute_rt or active) else None
                if isig and isig.get("status") != "valid" and (compute_rt or active):
                    reasons.append("GPU-using image is %s" % isig["status"])
                for label, _compute, mpath in rts:
                    msig = sig(mpath)
                    if msig and msig.get("status") not in ("valid", "not found"):
                        reasons.append("GPU runtime %s is %s: %s (tampered or substituted runtime indicator)"
                                       % (label, msig["status"], mpath))
                findings = [r for r in reasons if not r.startswith("note:")]
                sev = "high" if any("indicator" in r for r in findings) or len(findings) >= 2 else \
                    ("medium" if findings else "info")
                if isig is None and not self.opts["no_signatures"] and path:
                    isig = sig(path)
                yield 0, (pid, p.get("ppid") or 0, name, path or na("access denied"),
                          na(NOT_RECORDED) if cmd == NOT_RECORDED else cmd if cmd is not None else na("access denied"),
                          pid in windowed,
                          ("%s (%s)" % (isig["status"], isig.get("signer") or isig.get("kind") or "-")) if isig
                          else na(""),
                          ", ".join(sorted({r[0] for r in rts})) or (na("access denied") if mods is None else na("")),
                          "; ".join(sorted({r[2] for r in rts})) or na(""),
                          ", ".join("%s %.0f%%" % kv for kv in sorted(active.items())) or na(""),
                          human_size(g.get("dedicated") or 0), human_size(g.get("shared") or 0),
                          "; ".join(sorted({adapter_label(x) for x in g.get("luids") or []})) or na(""),
                          sev, "; ".join(sorted(set(reasons))) or na(""))
        if getattr(src, "win_debug_privilege", None) is False:
            self.log.warning("not elevated: system and other users' processes show 'access denied' (run as "
                             "Administrator to enable SeDebugPrivilege)")
        if not gpu.get("available"):
            self.log.warning("GPU performance counters unavailable: %s", gpu.get("error"))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("Path", str), ("CommandLine", str),
                         ("Window", bool), ("Signature", str), ("GPU runtimes", str), ("Runtime paths", str),
                         ("Active engines", str), ("Dedicated", str), ("Shared", str), ("Adapters", str),
                         ("Severity", str), ("Attention", str)], rows())
