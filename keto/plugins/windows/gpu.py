"""Windows: which processes use the GPU, through which runtime, and whether that fits what they are.

All in-the-wild GPU-evasion samples documented so far run on Windows: CoffeeLoader/ArmouryLoader decrypt
their payload with an OpenCL kernel, GPUGate gates execution on OpenCL being present, Cloak-and-Filter uses
the GPU for file-less execution, and GPU miners hide as background processes. The host-visible traces are
the GPU runtime DLLs a process loads and the per-process GPU engine and memory counters Windows keeps.
"""

from __future__ import annotations

import re

from keto.framework.exceptions import UnsupportedError
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import TreeGrid, na
from keto.framework.util import human_size
from keto.indicators import miners

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


def runtimes(mods):
    out = []
    for m in mods or []:
        n = (m.get("name") or "").lower()
        for rx, label, compute in _RT:
            if rx.match(n):
                out.append((label, compute, m.get("path") or n))
    return out


class GpuProcs(Plugin):
    NAME = "windows.gpuprocs"
    CATEGORY = "windows"
    DESCRIPTION = ("Lists every Windows process that uses the GPU or loads a GPU runtime (CUDA, NVRTC/PTX JIT, "
                   "OpenCL, DirectML, Vulkan, D3D12, NVAPI) with its GPU engine utilisation and GPU memory, and "
                   "flags GPU compute in windowless processes, GPU runtimes loaded from user-writable paths "
                   "(loader/dropper locations) and miner-like names.")
    METHOD = ("Toolhelp32 process and module snapshots plus QueryFullProcessImageNameW; EnumWindows for visible "
              "windows; PDH '\\GPU Engine(*)\\Utilization Percentage' (two samples) and '\\GPU Process Memory(*)\\"
              "Dedicated/Shared Usage', whose instance names carry the PID, adapter LUID and engine type.")
    ANALOG = "windows.pslist + windows.dlllist (GPU view)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("all", bool, False, "list every process, not only GPU users"),
                    Requirement("busy", float, 5.0, "engine utilisation % counted as active GPU work")]

    def run(self):
        src = self.ctx.live
        if (src.platform() or {}).get("system") != "Windows":
            raise UnsupportedError("windows.gpuprocs needs a live (or snapshotted) Windows system")
        procs = src.win_processes()
        by_pid = {p["pid"]: p for p in procs}
        own_window = set(src.win_windowed())
        gpu = src.win_gpu()
        counters = gpu.get("processes", {})

        def has_window(p):
            """Own visible window, or one owned by a same-image ancestor (browser/Electron GPU and renderer
            processes); a window of explorer.exe or another launcher is never inherited."""
            name = (p.get("name") or "").lower()
            seen = set()
            while p and p["pid"] not in seen:
                if p["pid"] in own_window:
                    return True
                seen.add(p["pid"])
                parent = by_pid.get(p.get("ppid"))
                p = parent if parent and (parent.get("name") or "").lower() == name else None
            return False

        def rows():
            for p in sorted(procs, key=lambda x: x["pid"]):
                pid = p["pid"]
                mods = src.win_modules(pid)
                rts = runtimes(mods)
                g = counters.get(str(pid)) or {}
                active = {e: u for e, u in (g.get("engines") or {}).items() if u >= self.opts["busy"]}
                if not (rts or active or g) and not self.opts["all"]:
                    continue
                name = p.get("name") or "?"
                path = p.get("path") or ""
                windowed = {pid} if has_window(p) else set()
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
                if active and pid not in windowed and name.lower() not in SYSTEM_GPU_USERS:
                    reasons.append("GPU engines busy without a visible window (%s)"
                                   % ", ".join("%s %.0f%%" % kv for kv in sorted(active.items())))
                for cat, ind in miners.classify(name.rsplit(".", 1)[0]) + miners.classify(path):
                    reasons.append("%s indicator in %s (%s)" % (cat, "image path", ind))
                findings = [r for r in reasons if not r.startswith("note:")]
                sev = "high" if any("indicator" in r for r in findings) or len(findings) >= 2 else \
                    ("medium" if findings else "info")
                yield 0, (pid, p.get("ppid") or 0, name, path or na("access denied"), pid in windowed,
                          ", ".join(sorted({r[0] for r in rts})) or (na("access denied") if mods is None else na("")),
                          ", ".join("%s %.0f%%" % kv for kv in sorted(active.items())) or na(""),
                          human_size(g.get("dedicated") or 0), human_size(g.get("shared") or 0),
                          len(g.get("luids") or []), sev, "; ".join(sorted(set(reasons))) or na(""))
        if not gpu.get("available"):
            self.log.warning("GPU performance counters unavailable: %s", gpu.get("error"))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("Path", str), ("Window", bool),
                         ("GPU runtimes", str), ("Active engines", str), ("Dedicated", str), ("Shared", str),
                         ("Adapters", int), ("Severity", str), ("Attention", str)], rows())
