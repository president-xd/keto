"""Live (or snapshot) GPU process analysis."""

from __future__ import annotations

import json
import ntpath
import re
import struct

from keto.formats import cubin as cubin_fmt
from keto.formats import fatbin as fatbin_fmt
from keto.formats import ptx as ptx_fmt
from keto.formats.elf import elf_extent
from keto.framework.exceptions import UnsupportedError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import Address, NotAvailableValue, TreeGrid, na
from keto.framework.util import utc_from_epoch
from keto.indicators import miners
from keto.live import procfs
from keto.live.source import NotRecordedError
from keto.plugins.windows import gpu as wgpu


def _gpu_memory(nvml: dict, pid: int):
    total, seen = 0, False
    for dev in nvml.get("devices", []):
        for key in ("compute_processes", "graphics_processes", "mps_compute_processes"):
            procs = dev.get(key)
            if isinstance(procs, list):
                for p in procs:
                    if p["pid"] == pid and p.get("used_memory") is not None:
                        total += p["used_memory"]
                        seen = True
    return total if seen else na("not reported")


class PsList(Plugin, TimeLinerInterface):
    NAME = "nvidia.pslist"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Lists processes using the GPU (PID, PPID, name, user, start time, GPU memory) and the "
                   "evidence that ties each one to the GPU.")
    METHOD = ("Merges NVML nvmlDeviceGet{Compute,Graphics,MPSCompute}RunningProcesses_v3 with a /proc walk: "
              "open GPU device nodes (/proc/<pid>/fd -> /dev/nvidia*, /dev/dxg) and mapped CUDA/NVIDIA runtime "
              "libraries (/proc/<pid>/maps). NVML PIDs absent from /proc are kept and marked. On Windows the "
              "process view is Toolhelp32 (name, PPID), QueryFullProcessImageNameW (image) and GetProcessTimes "
              "(start), and the evidence is NVML, the Windows GPU counters (PDH GPU Engine / GPU Process Memory) "
              "and GPU runtime DLLs in the module list; GPU memory falls back to the counters' dedicated usage when "
              "NVML (WDDM) has no per-process figure. Keto's own process is not listed.")
    ANALOG = "windows.pslist / linux.pslist"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def _procs(self):
        src = self.ctx.live
        return win_gpu_procs(self.ctx) if src.is_windows else procfs.gpu_processes(src)

    def run(self):
        src = self.ctx.live
        nv = src.nvml()
        if src.is_windows:
            return self._windows(src, nv)

        def rows():
            for pid, info in sorted(self._procs().items()):
                if self.opts["pid"] is not None and pid != self.opts["pid"]:
                    continue
                p = info["proc"]
                yield 0, (pid, p["ppid"] if p else na("not in /proc"), procfs.proc_name(p),
                          p["uid"] if p else na(""), utc_from_epoch(p["start_time"]) if p and p["start_time"]
                          else na("unknown"), _gpu_memory(nv, pid), ",".join(sorted(info["evidence"])),
                          procfs.exe_path(p) or na("unreadable"))
        return TreeGrid(PSLIST_COLUMNS, rows())

    def _windows(self, src, nv):
        counters = src.win_gpu().get("processes") or {}

        def rows():
            for pid, info in sorted(self._procs().items()):
                if self.opts["pid"] is not None and pid != self.opts["pid"]:
                    continue
                p = info["proc"]
                mem = _gpu_memory(nv, pid)
                if isinstance(mem, NotAvailableValue) and str(pid) in counters:
                    mem = counters[str(pid)].get("dedicated") or 0
                yield 0, (pid, p["ppid"] if p else na("not in process list"), win_name(p), na("Windows"),
                          utc_from_epoch(p["start_time"]) if p and p.get("start_time") else na("unknown"), mem,
                          ",".join(sorted(info["evidence"])),
                          (p or {}).get("path") or na("access denied" if p else "not in process list"))
        return TreeGrid(PSLIST_COLUMNS, rows())

    def generate_timeline(self):
        for pid, info in self._procs().items():
            p = info["proc"]
            if p and p.get("start_time"):
                name = win_name(p) if self.ctx.live.is_windows else procfs.proc_name(p)
                yield ("GPU process %s (%d) started" % (name, pid), "Created", utc_from_epoch(p["start_time"]))


PSLIST_COLUMNS = [("PID", int), ("PPID", int), ("Name", str), ("UID", int), ("Started", object), ("GPU Memory", int),
                  ("Evidence", str), ("Exe", str)]


# =====================================================================================================
# shared helpers for live plugins (also imported by live_system / live_malware)
# =====================================================================================================
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/memfd:", "memfd:")
HOME_PREFIXES = ("/home/", "/root/")
STANDARD_BIN_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
                     "/usr/lib/wsl/lib/", "/opt/nvidia/")
INJECTION_ENV = ("LD_PRELOAD", "LD_AUDIT", "CUDA_INJECTION64_PATH", "CUDA_INJECTION32_PATH", "NVTX_INJECTION64_PATH",
                 "NVTX_INJECTION32_PATH")
LOADER_ENV = ("VK_INSTANCE_LAYERS", "VK_LAYER_PATH", "VK_ADD_LAYER_PATH", "VK_ICD_FILENAMES", "VK_DRIVER_FILES",
              "VK_ADD_DRIVER_FILES", "OCL_ICD_FILENAMES", "OCL_ICD_VENDORS", "OPENCL_VENDOR_PATH",
              "__EGL_VENDOR_LIBRARY_FILENAMES", "__EGL_VENDOR_LIBRARY_DIRS")


def gpu_procs(ctx):
    """Cached ``procfs.gpu_processes`` for the context's live source."""
    return ctx.cached("live:gpu_processes", lambda: procfs.gpu_processes(ctx.live))


def win_gpu_procs(ctx):
    """Cached Windows GPU-process set (``windows.gpu.win_gpu_processes``): ``pid -> {proc, evidence, modules}``."""
    return ctx.cached("live:win_gpu_processes", lambda: wgpu.win_gpu_processes(ctx.live, win_all_modules(ctx)))


def win_all_modules(ctx):
    """Cached module list of every Windows process: ``pid -> [module] | None`` (None: access denied)."""
    src = ctx.live
    return ctx.cached("live:win_modules", lambda: {p["pid"]: src.win_modules(p["pid"]) for p in src.win_processes()})


def win_name(p) -> str:
    return (p or {}).get("name") or "?"


DISPLAY_CLASS = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
SERVICES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"
NVLDDMKM_KEY = SERVICES_KEY + r"\nvlddmkm"
#: where RmProfilingAdminOnly (GPU performance counters for administrators only) is set on Windows
RM_PROFILING_KEYS = (NVLDDMKM_KEY + r"\Global\NVTweak", NVLDDMKM_KEY + r"\Parameters\Global\NVTweak",
                     NVLDDMKM_KEY + r"\Parameters", NVLDDMKM_KEY)


def display_adapter_keys(src, nvidia_only: bool = False):
    """``[(key path, values)]`` of the display-class driver instance keys (``...\\{4d36e968-...}\\0000``...)."""
    out = []
    for sub in (src.registry_key(DISPLAY_CLASS) or {}).get("subkeys", []):
        if not re.match(r"^\d{4}$", sub):
            continue
        path = DISPLAY_CLASS + "\\" + sub
        vals = (src.registry_key(path) or {}).get("values") or {}
        nvidia = "nvidia" in str(vals.get("ProviderName", "")).lower() or \
            str(vals.get("MatchingDeviceId", "")).lower().startswith("pci\\ven_10de")
        if nvidia or not nvidia_only:
            out.append((path, vals))
    return out


#: display-class values naming the files of a display driver (user-mode driver and API drivers)
DRIVER_FILE_VALUES = ("UserModeDriverName", "UserModeDriverNameWow", "OpenCLDriverName", "OpenCLDriverNameWow",
                      "OpenGLDriverName", "OpenGLDriverNameWow", "VulkanDriverName", "VulkanDriverNameWow")


def win_driver_files(src):
    """``[(role, path)]`` of the NVIDIA display driver's files named in the registry: the kernel-mode driver
    (nvlddmkm ImagePath), the user-mode/API drivers of the NVIDIA display-class key, its DriverSupportModules
    (System32/SysWOW64 copy, else the driver-store folder) and System32\\nvml.dll / nvidia-smi.exe."""
    out, seen = [], set()

    def add(role, path):
        if isinstance(path, str) and path and path.lower() not in seen:
            seen.add(path.lower())
            out.append((role, path))
    root = wgpu.system_root(src)
    image = ((src.registry_key(NVLDDMKM_KEY) or {}).get("values") or {}).get("ImagePath")
    kmd = wgpu.win_path(src, str(image)) if image else ""
    add("kernel-mode driver", kmd)
    store = ntpath.dirname(kmd)
    for _key, vals in display_adapter_keys(src, nvidia_only=True):
        low = {k.lower(): v for k, v in vals.items()}
        for name in DRIVER_FILE_VALUES:
            v = low.get(name.lower())
            for path in v if isinstance(v, list) else [v]:
                add(name, path)
        for name, sysdir in (("driversupportmodules", "System32"), ("driversupportmoduleswow", "SysWOW64")):
            for mod in low.get(name) or []:
                if "\\" not in mod:
                    copy = "%s\\%s\\%s" % (root, sysdir, mod)
                    mod = copy if src.stat(copy) is not None or not store else ntpath.join(store, mod)
                add("DriverSupportModules", mod)
    add("NVML", root + "\\System32\\nvml.dll")
    add("nvidia-smi", root + "\\System32\\nvidia-smi.exe")
    return out


def win_rm_profiling(src):
    """``[(registry key, value)]`` of every RmProfilingAdminOnly value set for the NVIDIA driver."""
    found = []
    for key in RM_PROFILING_KEYS:
        v = ((src.registry_key(key) or {}).get("values") or {}).get("RmProfilingAdminOnly")
        if v is not None:
            found.append((key, v))
    for key, vals in display_adapter_keys(src, nvidia_only=True):
        if vals.get("RmProfilingAdminOnly") is not None:
            found.append((key, vals["RmProfilingAdminOnly"]))
    return found


#: NVIDIA and GPU-API DLLs recognised in Windows module lists
WIN_GPU_DLL_RE = re.compile(
    r"^(nvcuda\w*|nvapi\w*|nvwgf2um\w*|nvldumd\w*|nvd3dum\w*|nvoglv\w*|nvopencl\w*|nvml|nvencodeapi\w*|nvfbc\w*|"
    r"nvifr\w*|nvcuvid\w*|nvptxjitcompiler\w*|nvcudadebugger|nvoptix\w*|nvgpucomp\w*|nvrtc\w*|nvjitlink\w*|"
    r"cudart\w*|cublas\w*|cudnn\w*|cufft\w*|curand\w*|cusparse\w*|cusolver\w*|nccl\w*|cupti\w*|nvperf\w*|"
    r"nvtoolsext\w*|opencl|vulkan-1|d3d12|d3d12core|dxcore|directml)\.dll$", re.I)
#: temporary and download locations on Windows (the counterpart of /tmp, /dev/shm)
WIN_TEMP_RE = re.compile(r"\\(?:temp|tmp|downloads)\\|\\users\\public\\", re.I)
WIN_PROFILER_DLLS = ("cupti", "nvperf", "nvtoolsext", "nvtx")
WIN_CAPTURE_DLLS = ("nvfbc", "nvifr", "nvencodeapi")
WIN_DEBUG_DLLS = ("nvcudadebugger",)


def win_dlls(mods, prefixes):
    """File names of modules whose (lower-case) name starts with one of ``prefixes``."""
    return sorted({m.get("name") or wgpu.basename(m.get("path", "")) for m in mods or []
                   if (m.get("name") or "").lower().startswith(prefixes)})


def win_env(src, pid):
    """``(environment dict or None, reason when None)`` of a Windows process from its PEB."""
    try:
        info = src.win_process_info(pid)
    except NotRecordedError:
        return None, "not recorded in snapshot"
    if info is None:
        return None, "process not readable (access denied)"
    if info.get("environ") is None:
        return None, "environment block unreadable"
    return info["environ"], ""


def all_procs(ctx):
    def build():
        src = ctx.live
        out = {}
        for pid in src.pids():
            p = src.proc(pid)
            if p is not None:
                out[pid] = p
        return out
    return ctx.cached("live:all_processes", build)


def require_linux(src, what: str):
    if not src.is_linux:
        raise UnsupportedError("%s needs a Linux system (/proc, /sys); this source is %s"
                               % (what, (src.platform() or {}).get("system", "unknown")))


#: kernel-backed pseudo files that always appear as "(deleted)": shared anonymous memory, SysV shm
BENIGN_DELETED = ("/dev/zero", "/SYSV", "/drm mm object", "/i915")


def is_temp_path(path: str) -> bool:
    if not path or path.startswith(BENIGN_DELETED):
        return False
    return path.startswith(TEMP_PREFIXES) or path.endswith("(deleted)")


def path_risk(src, path: str):
    """``(suspicious, reason)`` for a library/command path named in a configuration file."""
    if not path:
        return False, ""
    if not path.startswith("/"):
        return False, "bare name resolved through the loader search path"
    if path.startswith(TEMP_PREFIXES):
        return True, "temporary / shared-memory location"
    if path.startswith(HOME_PREFIXES):
        return True, "user home directory (user-writable)"
    if src.stat(path) is None:
        return True, "referenced file does not exist"
    return False, ""


def win_path_risk(src, path: str):
    """``(suspicious, reason)`` for a DLL or manifest path named in Windows configuration (registry)."""
    if not path:
        return False, ""
    if "\\" not in path and "/" not in path:
        return False, "bare name resolved through the DLL search path"
    if WIN_TEMP_RE.search(path):
        return True, "temporary / download location"
    if wgpu.USER_WRITABLE.search(path):
        return True, "user-writable location"
    if src.stat(path) is None:
        return True, "referenced file does not exist"
    return False, ""


def mapped_files(proc: dict):
    """Group /proc/<pid>/maps entries by backing file: ``[{path, base, end, perms}]``."""
    out = {}
    for m in (proc or {}).get("maps", []):
        path = m.get("path", "")
        if not path or path.startswith("["):
            continue
        e = out.setdefault(path, {"path": path, "base": m["start"], "end": m["end"], "perms": set()})
        e["base"], e["end"] = min(e["base"], m["start"]), max(e["end"], m["end"])
        e["perms"].add(m["perms"])
    for e in out.values():
        e["perms"] = ",".join(sorted(e["perms"]))
    return sorted(out.values(), key=lambda e: e["base"])


def read_params(src) -> dict:
    """``/proc/driver/nvidia/params`` as a dict (empty when unavailable)."""
    out = {}
    for line in (src.read_text("/proc/driver/nvidia/params") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


MODPROBE_DIRS = ("/etc/modprobe.d", "/lib/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d")


def modprobe_entries(src):
    """Parse modprobe.d files: ``[{file, kind, module, key, value, line}]``."""
    out = []
    for d in MODPROBE_DIRS:
        for path in src.glob_dir(d, r"\.conf$"):
            for line in (src.read_text(path) or "").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                kind = parts[0]
                module = parts[1] if len(parts) > 1 else ""
                if kind == "options":
                    for opt in parts[2:]:
                        k, _, v = opt.partition("=")
                        out.append({"file": path, "kind": kind, "module": module, "key": k, "value": v, "line": line})
                else:
                    out.append({"file": path, "kind": kind, "module": module, "key": "", "value": " ".join(parts[2:]),
                                "line": line})
    return out


def env_finding(key: str, value: str, windows: bool = False):
    """``(suspicious, reason)`` for one environment variable of a GPU process. Windows variable names are
    case-insensitive and its temporary/user-writable locations are AppData, Temp, Downloads..."""
    if windows:
        key = key.upper()
        if key in LOADER_ENV:
            temp = bool(wgpu.USER_WRITABLE.search(value) or WIN_TEMP_RE.search(value))
            return temp, "GPU API loader override" + (" pointing to a user-writable directory" if temp else "")
    if key in ("LD_PRELOAD", "LD_AUDIT"):
        return True, "library injected into the process by the dynamic loader (%s)" % key
    if key in ("CUDA_INJECTION64_PATH", "CUDA_INJECTION32_PATH"):
        return True, "CUDA driver loads this library into the process at cuInit (CUPTI injection hook)"
    if key in ("NVTX_INJECTION64_PATH", "NVTX_INJECTION32_PATH"):
        return True, "NVTX loads this library into the process (tool injection hook)"
    if key == "LD_LIBRARY_PATH":
        temp = [s for s in value.split(":") if s.startswith(TEMP_PREFIXES) or s in ("/tmp", "/dev/shm", "/var/tmp")]
        return (True, "library search path includes temporary directory %s" % ",".join(temp)) if temp \
            else (False, "library search path override")
    if key in LOADER_ENV:
        temp = any(t in value for t in ("/tmp", "/dev/shm", "/var/tmp"))
        return temp, "GPU API loader override" + (" pointing to a temporary directory" if temp else "")
    if key == "CUDA_LAUNCH_BLOCKING":
        return False, "synchronous kernel launches (debugging aid)" if value not in ("", "0") else ""
    if key in ("CUDA_VISIBLE_DEVICES", "NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES"):
        return False, "GPU selection / container GPU exposure"
    if key.startswith("CUDA_MPS_"):
        return False, "CUDA MPS client configuration"
    if key.startswith("CUDA_CACHE_"):
        return False, "JIT ComputeCache configuration (changes where cache evidence lives)"
    if key in ("CUDA_DEBUGGER_SOFTWARE_PREEMPTION", "CUDA_ENABLE_COREDUMP_ON_EXCEPTION", "CUDA_COREDUMP_FILE"):
        return False, "CUDA debugger / core-dump setting"
    if key.startswith(("__GL_", "__NV_")):
        return False, "NVIDIA OpenGL/driver override"
    return False, ""


def pid_filter(opts, pid) -> bool:
    return opts.get("pid") is None or opts["pid"] == pid


# =====================================================================================================
# process plugins
# =====================================================================================================
class PsTree(Plugin):
    NAME = "nvidia.pstree"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Shows GPU processes inside their process tree, including every non-GPU ancestor up to init, "
                   "so the launcher of each GPU workload is visible.")
    METHOD = ("Starts from the nvidia.pslist set (NVML process lists + /proc GPU evidence) and follows PPid from "
              "/proc/<pid>/status upwards; ancestors without GPU evidence are included and marked GPU=False. On "
              "Windows the parent links are Toolhelp32 PPIDs (a parent that started after its child holds a reused "
              "PID and is not linked) and command lines come from each PEB.")
    ANALOG = "windows.pstree / linux.pstree"
    SOURCES = ("live",)

    def _windows(self, src):
        procs = win_gpu_procs(self.ctx)
        by_pid = {p["pid"]: p for p in src.win_processes()}
        nodes = {pid: info["proc"] for pid, info in procs.items()}
        parent_of = {}
        for pid in list(nodes):
            p, seen = nodes[pid], set()
            while p:
                parent = by_pid.get(p.get("ppid"))
                if not parent or parent["pid"] in (p["pid"], 0) or parent["pid"] in seen:
                    break
                if p.get("start_time") and parent.get("start_time") and parent["start_time"] > p["start_time"]:
                    break  # the real parent exited and its PID was reused
                parent_of[p["pid"]] = parent["pid"]
                if parent["pid"] in nodes:
                    break
                seen.add(parent["pid"])
                nodes[parent["pid"]] = parent
                p = parent
        children, roots = {}, []
        for pid in nodes:
            ppid = parent_of.get(pid)
            if ppid in nodes:
                children.setdefault(ppid, []).append(pid)
            else:
                roots.append(pid)

        def walk(pid, depth, guard):
            p = nodes.get(pid)
            info = procs.get(pid)
            cmd = src.win_cmdline(pid) if p else None
            yield depth, (pid, p["ppid"] if p else na("not in process list"), win_name(p), info is not None,
                          ",".join(sorted(info["evidence"])) if info else "",
                          cmd if cmd else na("empty/unreadable"))
            for c in sorted(children.get(pid, [])):
                if c not in guard:
                    yield from walk(c, depth + 1, guard | {c})

        def rows():
            for r in sorted(roots):
                yield from walk(r, 0, {r})
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("GPU", bool), ("Evidence", str),
                         ("Cmdline", str)], rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
        procs = gpu_procs(self.ctx)
        nodes = {pid: info["proc"] for pid, info in procs.items()}
        for pid in list(nodes):
            p, seen = nodes[pid], set()
            while p and p.get("ppid") and p["ppid"] not in nodes and p["ppid"] not in seen:
                seen.add(p["ppid"])
                parent = src.proc(p["ppid"])
                nodes[p["ppid"]] = parent
                p = parent
        children, roots = {}, []
        for pid, p in nodes.items():
            ppid = p.get("ppid") if p else None
            if ppid in nodes and ppid != pid:
                children.setdefault(ppid, []).append(pid)
            else:
                roots.append(pid)

        def walk(pid, depth, guard):
            p = nodes.get(pid)
            info = procs.get(pid)
            yield depth, (pid, p["ppid"] if p else na("not in /proc"), procfs.proc_name(p), info is not None,
                          ",".join(sorted(info["evidence"])) if info else "",
                          " ".join(p["cmdline"]) if p and p.get("cmdline") else na("empty/unreadable"))
            for c in sorted(children.get(pid, [])):
                if c not in guard:
                    yield from walk(c, depth + 1, guard | {c})

        def rows():
            for r in sorted(roots):
                yield from walk(r, 0, {r})
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("GPU", bool), ("Evidence", str),
                         ("Cmdline", str)], rows())


class CmdLine(Plugin):
    NAME = "nvidia.cmdline"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = "Shows the full command line and executable of every GPU process."
    METHOD = ("Reads /proc/<pid>/cmdline (NUL-separated argv) and the /proc/<pid>/exe link for each nvidia.pslist "
              "PID; on Windows the PEB's ProcessParameters->CommandLine and QueryFullProcessImageNameW.")
    ANALOG = "windows.cmdline / linux.psaux"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            def wrows():
                for pid, info in sorted(win_gpu_procs(self.ctx).items()):
                    p = info["proc"]
                    if not pid_filter(self.opts, pid):
                        continue
                    cmd = src.win_cmdline(pid) if p else None
                    yield 0, (pid, win_name(p), (p or {}).get("path") or na("access denied" if p else
                                                                            "not in process list"),
                              cmd if cmd else na("empty/unreadable"))
            return TreeGrid([("PID", int), ("Name", str), ("Exe", str), ("Args", str)], wrows())

        def rows():
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                if not pid_filter(self.opts, pid):
                    continue
                p = info["proc"]
                yield 0, (pid, procfs.proc_name(p), procfs.exe_path(p) or na("unreadable"),
                          " ".join(p["cmdline"]) if p and p.get("cmdline") else na("empty/unreadable"))
        return TreeGrid([("PID", int), ("Name", str), ("Exe", str), ("Args", str)], rows())


class Envars(Plugin):
    NAME = "nvidia.envars"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Shows GPU-relevant environment variables of GPU processes and flags injection vectors "
                   "(LD_PRELOAD/LD_AUDIT, CUDA_INJECTION64_PATH, NVTX_INJECTION64_PATH, loader overrides into "
                   "temporary directories).")
    METHOD = ("Reads /proc/<pid>/environ (reduced at the source to GPU/loader-relevant keys for privacy) and "
              "classifies each key: injection hooks are suspicious; GPU selection, MPS, ComputeCache and debugger "
              "settings are reported as context. On Windows the environment block comes from each GPU process's "
              "PEB (ProcessParameters->Environment via ReadProcessMemory), reduced the same way, with names "
              "compared case-insensitively.")
    ANALOG = "windows.envars / linux.envars"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"),
                    Requirement("suspicious_only", bool, False, "only suspicious variables"),
                    Requirement("all", bool, False, "also show retained variables with no finding (PATH, HOME...)")]

    def run(self):
        src = self.ctx.live
        windows = src.is_windows
        if not (windows or src.is_linux):
            require_linux(src, self.NAME)

        def environments():
            if windows:
                for pid, info in sorted(win_gpu_procs(self.ctx).items()):
                    if pid_filter(self.opts, pid) and info["proc"] is not None:
                        env, why = win_env(src, pid)
                        yield pid, win_name(info["proc"]), env, why
                return
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                p = info["proc"]
                if pid_filter(self.opts, pid) and p is not None:
                    yield pid, procfs.proc_name(p), p.get("environ"), "environ unreadable (permission)"

        def rows():
            for pid, name, env, why in environments():
                if env is None:
                    if not self.opts["suspicious_only"]:
                        yield 0, (pid, name, na(why), na(""), False, "")
                    continue
                for k in sorted(env):
                    sus, reason = env_finding(k, env[k], windows)
                    if self.opts["suspicious_only"] and not sus:
                        continue
                    if not reason and not self.opts["all"]:
                        continue
                    yield 0, (pid, name, k, env[k], sus, reason)
        return TreeGrid([("PID", int), ("Name", str), ("Variable", str), ("Value", str), ("Suspicious", bool),
                         ("Reason", str)], rows())


def node_kind(target: str) -> str:
    name = target[len("/dev/"):] if target.startswith("/dev/") else target
    if name == "nvidiactl":
        return "control node (RM client handle)"
    if re.match(r"nvidia\d+$", name):
        return "GPU device node"
    if name == "nvidia-uvm":
        return "unified memory (UVM)"
    if name == "nvidia-uvm-tools":
        return "UVM tools (profiling/debug event stream)"
    if name == "nvidia-modeset":
        return "display modeset"
    if name.startswith("nvidia-caps/"):
        return "capability node (MIG/admin)"
    if name == "dxg":
        return "WSL2 GPU paravirtualisation (dxgkrnl)"
    if name.startswith("dri/renderD"):
        return "DRM render node"
    if name.startswith("dri/card"):
        return "DRM card node"
    if name.startswith("nvidia-nvswitch") or name == "nvidia-nvlink":
        return "NVSwitch/NVLink management"
    return "GPU-related node"


class Handles(Plugin):
    NAME = "nvidia.handles"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Lists every open GPU device-node file descriptor per process (control, GPU, UVM, modeset, caps, "
                   "dxg); on Windows every open handle to a GPU object or file (DxgKrnl/NVIDIA devices, the CUDA "
                   "driver's kernel archive, shader and JIT caches in use, NVIDIA capture components).")
    METHOD = ("Resolves each /proc/<pid>/fd/<n> symlink and keeps targets matching /dev/nvidia*, /dev/nvidia-caps/*, "
              "/dev/dxg and DRM nodes; the node type tells what the process can do (e.g. nvidia-uvm-tools = event "
              "tracing, nvidiactl = RM object allocation). Windows (where GPU work goes through dxgkrnl system calls, "
              "not a device file): one snapshot of the system handle table (NtQuerySystemInformation "
              "SystemExtendedHandleInformation); each File handle is duplicated into Keto (PROCESS_DUP_HANDLE: same "
              "user, or Administrator) and named with NtQueryObject in a worker thread with a timeout (a name query "
              "on a synchronous file object can block; a stuck worker is abandoned); only GPU-related names are kept, "
              "with their NT paths.")
    ANALOG = "windows.handles / linux.lsof"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def _windows(self, src):
        self_pid = (src.platform() or {}).get("self_pid")

        def rows():
            unchecked = []
            for p in sorted(src.win_processes(), key=lambda x: x["pid"]):
                pid = p["pid"]
                if pid in (0, 4) or pid == self_pid or not pid_filter(self.opts, pid):
                    continue
                try:
                    info = src.win_handles(pid)
                except NotRecordedError:
                    info = None
                if info is None:
                    unchecked.append(pid)
                    continue
                for h in info.get("handles", []):
                    yield 0, (pid, win_name(p), h["handle"], h["name"], h["kind"])
            if unchecked:
                self.log.warning("%d process(es) not checked: their handles cannot be duplicated (run as "
                                 "Administrator for other users' and service processes): %s", len(unchecked),
                                 ", ".join(map(str, unchecked[:20])))
        return TreeGrid([("PID", int), ("Name", str), ("FD", int), ("Device", str), ("Kind", str)], rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
        require_linux(src, self.NAME)

        def rows():
            for pid, p in sorted(all_procs(self.ctx).items()):
                if not pid_filter(self.opts, pid):
                    continue
                for fd, target in procfs.gpu_fds(p):
                    yield 0, (pid, procfs.proc_name(p), fd, target, node_kind(target))
        return TreeGrid([("PID", int), ("Name", str), ("FD", int), ("Device", str), ("Kind", str)], rows())


class Libs(Plugin):
    NAME = "nvidia.libs"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Lists GPU runtime libraries (CUDA, NVML, cuBLAS/cuDNN, OpenCL/Vulkan/EGL NVIDIA drivers, WSL "
                   "dxcore) mapped in each GPU process, plus any library mapped from a temporary, deleted or "
                   "fileless location.")
    METHOD = ("Groups /proc/<pid>/maps entries by backing file; GPU libraries are recognised by name; paths under "
              "/tmp, /var/tmp, /dev/shm, /run/user, memfd: or marked '(deleted)' are flagged. On Windows the module "
              "list (Toolhelp32 module snapshot) of each GPU process is used: NVIDIA/GPU-API DLLs are recognised by "
              "name, any DLL from a Temp/Downloads/Public folder and GPU DLLs from a user-writable folder (AppData, "
              "ProgramData, Desktop...) are flagged; module protections are not part of that list.")
    ANALOG = "windows.dlllist / linux.library_list"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"),
                    Requirement("all_libs", bool, False, "list every file-backed mapping, not only GPU/suspicious ones")]

    def _windows(self):
        def rows():
            for pid, info in sorted(win_gpu_procs(self.ctx).items()):
                p = info["proc"]
                if p is None or not pid_filter(self.opts, pid):
                    continue
                if info["modules"] is None:
                    yield 0, (pid, win_name(p), na(""), na(""), na(""), na("module list unreadable (access denied)"),
                              False, False, "")
                    continue
                for m in sorted(info["modules"], key=lambda x: x.get("base") or 0):
                    path = m.get("path") or m.get("name") or ""
                    gpu = bool(WIN_GPU_DLL_RE.match(m.get("name") or ""))
                    temp = bool(WIN_TEMP_RE.search(path))
                    writable_gpu = gpu and bool(wgpu.USER_WRITABLE.search(path))
                    if not (gpu or temp or self.opts["all_libs"]):
                        continue
                    reason = "temporary / download location" if temp else \
                        "GPU library loaded from a user-writable location" if writable_gpu else ""
                    base = m.get("base") or 0
                    yield 0, (pid, win_name(p), Address(base), Address(base + (m.get("size") or 0)), na(""), path,
                              gpu, temp or writable_gpu, reason)
        return TreeGrid(LIBS_COLUMNS, rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows()
        require_linux(src, self.NAME)

        def rows():
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                p = info["proc"]
                if p is None or not pid_filter(self.opts, pid):
                    continue
                for e in mapped_files(p):
                    path = e["path"]
                    gpu = bool(procfs.GPU_LIB_RE.search(path))
                    executable = "x" in e["perms"]
                    sus = is_temp_path(path) and (gpu or executable or not path.endswith("(deleted)"))
                    if "memfd:" in path and not executable:
                        sus = False  # data-only memfd buffers are routine (Wayland, audio, browsers)
                    if not (gpu or sus or self.opts["all_libs"]):
                        continue
                    reason = ""
                    if sus and "memfd:" in path:
                        reason = "fileless (memfd) executable mapping"
                    elif sus and path.endswith("(deleted)"):
                        reason = "backing file deleted from disk"
                    elif sus:
                        reason = "temporary / shared-memory location"
                    yield 0, (pid, procfs.proc_name(p), Address(e["base"]), Address(e["end"]), e["perms"], path,
                              gpu, sus, reason)
        return TreeGrid(LIBS_COLUMNS, rows())


LIBS_COLUMNS = [("PID", int), ("Name", str), ("Base", Address), ("End", Address), ("Perms", str), ("Path", str),
                ("GPU library", bool), ("Suspicious", bool), ("Reason", str)]


def nvml_devices(src):
    nv = src.nvml()
    if not nv.get("available"):
        raise UnsupportedError("NVML is not available: %s" % nv.get("error", "unknown error"))
    return nv, nv.get("devices", [])


def _na_of(value):
    return na(value["_na"]) if isinstance(value, dict) and "_na" in value else None


class Sessions(Plugin):
    NAME = "nvidia.sessions"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Lists hardware video-encoder (NVENC) and frame-buffer-capture (NvFBC) sessions per GPU with the "
                   "owning process, codec/type, resolution and frame rate.")
    METHOD = "nvmlDeviceGetEncoderSessions and nvmlDeviceGetFBCSessions per device; owners resolved through /proc/<pid>/comm."
    ANALOG = "windows.sessions"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        _, devices = nvml_devices(src)

        def rows():
            for d in devices:
                for kind, key in (("NVENC", "encoder_sessions"), ("FBC", "fbc_sessions")):
                    sessions = d.get(key)
                    bad = _na_of(sessions)
                    if bad is not None or not isinstance(sessions, list):
                        yield 0, (d.get("index"), kind, bad or na("not collected"), na(""), "", "", "", na(""), na(""))
                        continue
                    for s in sessions:
                        yield 0, (d.get("index"), kind, s.get("session_id"), s.get("pid"),
                                  procfs.proc_name(src.proc(s.get("pid"))) if s.get("pid") else "?",
                                  s.get("codec") or s.get("type") or "", s.get("resolution", ""),
                                  s.get("avg_fps"), s.get("avg_latency_us"))
        return TreeGrid([("GPU", int), ("Kind", str), ("Session", int), ("PID", int), ("Process", str),
                         ("Codec/Type", str), ("Resolution", str), ("FPS", int), ("Latency us", int)], rows())


class Accounting(Plugin, TimeLinerInterface):
    NAME = "nvidia.accounting"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Shows NVML accounting history: every process that used the GPU while accounting mode was on, "
                   "including processes that have already exited, with start time, duration, peak memory and "
                   "utilisation (GPU execution evidence).")
    METHOD = ("nvmlDeviceGetAccountingMode, nvmlDeviceGetAccountingPids and nvmlDeviceGetAccountingStats "
              "(startTime in microseconds since the epoch, time in ms, isRunning) per device.")
    ANALOG = "windows.registry.amcache / windows.registry.userassist (execution history)"
    SOURCES = ("live",)

    def _entries(self):
        src = self.ctx.live
        _, devices = nvml_devices(src)
        for d in devices:
            acc = d.get("accounting")
            yield d, acc

    def run(self):
        src = self.ctx.live

        def rows():
            for d, acc in self._entries():
                bad = _na_of(acc)
                if bad is not None or not isinstance(acc, dict):
                    yield 0, (d.get("index"), na(""), "", na(""), bad or na("not collected"), na(""), na(""), na(""),
                              na(""))
                    continue
                mode = d.get("accounting_mode")
                if not acc and mode != 1:
                    state = "disabled" if mode == 0 else "unknown (%s)" % (_na_of(mode) or mode)
                    yield 0, (d.get("index"), na(""), "", na(""),
                              na("accounting mode %s: no history is recorded (enable with nvidia-smi -am 1)" % state),
                              na(""), na(""), na(""), na(""))
                    continue
                for pid_s, st in sorted(acc.items(), key=lambda kv: int(kv[0])):
                    pid = int(pid_s)
                    if _na_of(st) is not None:
                        yield 0, (d.get("index"), pid, "", na(""), _na_of(st), na(""), na(""), na(""), na(""))
                        continue
                    p = src.proc(pid)
                    start = utc_from_epoch(st["start_time_us"] / 1e6) if st.get("start_time_us") else na("unknown")
                    yield 0, (d.get("index"), pid, procfs.proc_name(p) if p else "(exited / not in /proc)",
                              bool(st.get("running")), start, round(st.get("time_ms", 0) / 1000.0, 1),
                              st.get("gpu_util"), st.get("mem_util"),
                              st.get("max_memory") if st.get("max_memory") is not None else na("unknown"))
        return TreeGrid([("GPU", int), ("PID", int), ("Process", str), ("Running", bool), ("Started", object),
                         ("Duration s", float), ("GPU util %", int), ("Mem util %", int), ("Max memory", int)], rows())

    def generate_timeline(self):
        for d, acc in self._entries():
            if not isinstance(acc, dict) or _na_of(acc) is not None:
                continue
            for pid_s, st in acc.items():
                if _na_of(st) is not None or not st.get("start_time_us"):
                    continue
                start = st["start_time_us"] / 1e6
                yield ("GPU%s accounting: PID %s started using the GPU" % (d.get("index"), pid_s), "Created",
                       utc_from_epoch(start))
                if not st.get("running"):
                    yield ("GPU%s accounting: PID %s finished (%.0fs, %s%% GPU)" % (
                        d.get("index"), pid_s, st.get("time_ms", 0) / 1000.0, st.get("gpu_util")), "Ended",
                        utc_from_epoch(start + st.get("time_ms", 0) / 1000.0))


DEBUG_TOOLS = {"cuda-gdb", "cuda-gdbserver", "nsys", "ncu", "ncu-ui", "nsight-sys", "nsys-ui", "compute-sanitizer",
               "cuda-memcheck", "nv-nsight-cu-cli"}
WIN_DEBUG_TOOLS = {"ngfx.exe", "ngfx-ui.exe", "ngfx-capture.exe"}  # Nsight Graphics


class Debugger(Plugin):
    NAME = "nvidia.debugger"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Finds GPU debugging activity: processes with the CUDA debugger backend loaded, GPU processes "
                   "ptrace-attached by another process, and running GPU debugger/profiler tools.")
    METHOD = ("Looks for libcudadebugger.so in /proc/<pid>/maps, TracerPid in /proc/<pid>/status for GPU "
              "processes, tool names (cuda-gdb, nsys, ncu, compute-sanitizer...) in comm/exe, and CUDA debugger "
              "environment settings. On Windows: nvcudadebugger.dll in any process's module list, "
              "NtQueryInformationProcess(ProcessDebugPort) for GPU processes (a user-mode debugger is attached), "
              "Nsight/CUDA tool image names (nsys, ncu, ngfx, compute-sanitizer...) and the same variables in the "
              "PEB environment.")
    ANALOG = "windows.debugregisters / linux.ptrace"
    SOURCES = ("live",)

    def _windows(self, src):
        gpu = win_gpu_procs(self.ctx)
        mods = win_all_modules(self.ctx)
        tools = {t + ".exe" for t in DEBUG_TOOLS} | WIN_DEBUG_TOOLS
        self_pid = (src.platform() or {}).get("self_pid")

        def rows():
            unchecked = []
            for p in sorted(src.win_processes(), key=lambda x: x["pid"]):
                pid, name = p["pid"], win_name(p)
                if pid == self_pid:
                    continue
                for dll in win_dlls(mods.get(pid), WIN_DEBUG_DLLS):
                    yield 0, (pid, name, "CUDA debugger backend loaded",
                              "%s loaded: the process can be (or is being) debugged on the GPU" % dll)
                if name.lower() in tools:
                    yield 0, (pid, name, "GPU debugger/profiler tool running",
                              src.win_cmdline(pid) or p.get("path") or "")
                if pid not in gpu:
                    continue
                try:
                    info = src.win_process_info(pid) or {}
                except NotRecordedError:
                    info = {}
                if info.get("debugged") is None and pid not in (0, 4):
                    unchecked.append(pid)
                if info.get("debugged"):
                    yield 0, (pid, name, "debugger attached", "ProcessDebugPort is set: a user-mode debugger is "
                                                              "attached to this GPU process")
                env = info.get("environ") or {}
                for k in sorted(env):
                    if k.upper() in ("CUDA_DEBUGGER_SOFTWARE_PREEMPTION", "CUDA_ENABLE_COREDUMP_ON_EXCEPTION") \
                            and env[k]:
                        yield 0, (pid, name, "debugger setting", "%s=%s" % (k, env[k]))
            if unchecked:
                self.log.warning("%d GPU process(es) not checked for an attached debugger: ProcessDebugPort "
                                 "unreadable (run as Administrator): %s", len(unchecked),
                                 ", ".join(map(str, unchecked[:20])))
        return TreeGrid([("PID", int), ("Name", str), ("Indicator", str), ("Details", str)], rows())

    def run(self):
        if self.ctx.live.is_windows:
            return self._windows(self.ctx.live)
        require_linux(self.ctx.live, self.NAME)
        procs = all_procs(self.ctx)
        gpu = gpu_procs(self.ctx)

        def rows():
            for pid, p in sorted(procs.items()):
                name = procfs.proc_name(p)
                if procfs.has_lib(p, procfs.DEBUG_LIBS):
                    yield 0, (pid, name, "CUDA debugger backend loaded",
                              "libcudadebugger mapped: the process can be (or is being) debugged on the GPU")
                if p.get("tracer_pid") and pid in gpu:
                    tracer = procs.get(p["tracer_pid"])
                    yield 0, (pid, name, "ptrace-attached",
                              "TracerPid %d (%s)" % (p["tracer_pid"], procfs.proc_name(tracer)))
                exe_base = procfs.exe_path(p).rsplit("/", 1)[-1]
                if name in DEBUG_TOOLS or exe_base in DEBUG_TOOLS:
                    yield 0, (pid, name, "GPU debugger/profiler tool running", " ".join(p.get("cmdline") or []))
                for k in ("CUDA_DEBUGGER_SOFTWARE_PREEMPTION", "CUDA_ENABLE_COREDUMP_ON_EXCEPTION"):
                    if (p.get("environ") or {}).get(k):
                        yield 0, (pid, name, "debugger setting", "%s=%s" % (k, p["environ"][k]))
        return TreeGrid([("PID", int), ("Name", str), ("Indicator", str), ("Details", str)], rows())


class Profiling(Plugin):
    NAME = "nvidia.profiling"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Reports GPU performance-counter exposure (RmProfilingAdminOnly, the CVE-2018-6260 "
                   "side-channel mitigation) and processes using profiling/tracing interfaces (CUPTI, nvperf, NVTX "
                   "injection, /dev/nvidia-uvm-tools).")
    METHOD = ("Reads RmProfilingAdminOnly from /proc/driver/nvidia/params and NVreg_RestrictProfilingToAdminUsers "
              "from modprobe.d; per process checks mapped libcupti/libnvperf/libnvToolsExt, fds on "
              "/dev/nvidia-uvm-tools and injection variables. On Windows RmProfilingAdminOnly is read from the "
              "nvlddmkm service keys (Global\\NVTweak, Parameters) and the NVIDIA display-class key, and each GPU "
              "process's modules (cupti*, nvperf*, nvToolsExt*) and PEB environment are checked.")
    ANALOG = "linux.tracing.perf_events"
    SOURCES = ("live",)

    def _windows(self, src):
        def rows():
            found = win_rm_profiling(src)
            if src.registry_key(NVLDDMKM_KEY) is None:
                yield 0, ("system", na(""), "registry", "RmProfilingAdminOnly",
                          na("no NVIDIA display driver (nvlddmkm service) installed"), "unknown")
            elif not found:
                yield 0, ("system", na(""), "registry", "RmProfilingAdminOnly",
                          "not set: the driver default applies (GPU performance counters restricted to "
                          "administrators since the CVE-2018-6260 fix, R419.67)", "info")
            for key, v in found:
                exposed = str(v).strip() == "0"
                yield 0, ("system", na(""), key, "RmProfilingAdminOnly=%s" % v,
                          "GPU performance counters usable by non-admin users (side channel, CVE-2018-6260)"
                          if exposed else "performance counters restricted to administrators",
                          "high" if exposed else "info")
            for pid, info in sorted(win_gpu_procs(self.ctx).items()):
                p = info["proc"]
                if p is None:
                    continue
                name = win_name(p)
                for dll in win_dlls(info["modules"], WIN_PROFILER_DLLS):
                    yield 0, ("process", pid, name, "profiling library", dll, "low")
                env, _why = win_env(src, pid)
                for k in sorted(env or {}):
                    if k.upper() in ("CUDA_INJECTION64_PATH", "NVTX_INJECTION64_PATH") and env[k]:
                        yield 0, ("process", pid, name, k.upper(), env[k], "high")
        return TreeGrid(PROFILING_COLUMNS, rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
        require_linux(src, self.NAME)
        params = read_params(src)

        def rows():
            v = params.get("RmProfilingAdminOnly")
            if v is None:
                yield 0, ("system", na(""), "", "RmProfilingAdminOnly", na("/proc/driver/nvidia/params unreadable"),
                          "unknown")
            else:
                exposed = v.strip() == "0"
                yield 0, ("system", na(""), "", "RmProfilingAdminOnly=%s" % v,
                          "GPU performance counters usable by non-admin users (side channel, CVE-2018-6260)"
                          if exposed else "performance counters restricted to administrators",
                          "high" if exposed else "info")
            for e in modprobe_entries(src):
                if e["key"] == "NVreg_RestrictProfilingToAdminUsers":
                    yield 0, ("system", na(""), e["file"], "%s=%s" % (e["key"], e["value"]),
                              "modprobe option " + ("disables" if e["value"] == "0" else "enables")
                              + " the profiling restriction", "high" if e["value"] == "0" else "info")
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                p = info["proc"]
                if p is None:
                    continue
                name = procfs.proc_name(p)
                for lib in procfs.has_lib(p, procfs.PROFILER_LIBS):
                    yield 0, ("process", pid, name, "profiling library", lib, "low")
                for fd, target in procfs.gpu_fds(p):
                    if target.endswith("nvidia-uvm-tools"):
                        yield 0, ("process", pid, name, "UVM tools fd %d" % fd,
                                  "subscribed to UVM event tracing (profiler/debugger interface)", "medium")
                for k in ("CUDA_INJECTION64_PATH", "NVTX_INJECTION64_PATH"):
                    if (p.get("environ") or {}).get(k):
                        yield 0, ("process", pid, name, k, p["environ"][k], "high")
        return TreeGrid(PROFILING_COLUMNS, rows())


PROFILING_COLUMNS = [("Scope", str), ("PID", int), ("Name/Source", str), ("Indicator", str), ("Details", str),
                     ("Risk", str)]


CONTAINER_RES = [(re.compile(r"docker[-/]([0-9a-f]{12,64})"), "docker"),
                 (re.compile(r"cri-containerd-([0-9a-f]{12,64})"), "containerd"),
                 (re.compile(r"crio-([0-9a-f]{12,64})"), "cri-o"),
                 (re.compile(r"libpod-([0-9a-f]{12,64})"), "podman"),
                 (re.compile(r"kubepods\S*?([0-9a-f]{64})"), "kubernetes"),
                 (re.compile(r"lxc\.payload\.([\w.-]+)|/lxc/([\w.-]+)"), "lxc")]
TOOLKIT_CVES = [("CVE-2024-0132", (1, 16, 2), "TOCTOU in the container toolkit: crafted image can access the host "
                 "filesystem (container escape)"),
                ("CVE-2025-23266", (1, 17, 8), "\"NVIDIAScape\": LD_PRELOAD in the createContainer OCI hook gives "
                 "root on the host (container escape)")]


def container_of(cgroup: str):
    for rx, runtime in CONTAINER_RES:
        m = rx.search(cgroup or "")
        if m:
            cid = next(g for g in m.groups() if g)
            return runtime, cid[:12]
    return None, None


def toolkit_version(src):
    r = src.command(["dpkg-query", "-W", "-f=${Version}", "nvidia-container-toolkit"])
    if r and r.get("rc") == 0 and r.get("stdout", "").strip():
        return r["stdout"].strip(), "dpkg"
    r = src.command(["rpm", "-q", "--qf", "%{VERSION}", "nvidia-container-toolkit"])
    if r and r.get("rc") == 0 and r.get("stdout", "").strip() and "not installed" not in r["stdout"]:
        return r["stdout"].strip(), "rpm"
    for p in ("/usr/bin/nvidia-ctk", "/usr/bin/nvidia-container-cli", "/usr/bin/nvidia-container-runtime-hook"):
        if src.stat(p) is not None:
            return None, "binary present (%s), version unknown" % p
    return None, None


class Containers(Plugin):
    NAME = "nvidia.containers"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Finds GPU processes running inside containers (Docker, containerd, CRI-O, Podman, Kubernetes, "
                   "LXC) and checks the NVIDIA Container Toolkit version against known container-escape CVEs "
                   "(CVE-2024-0132 fixed in 1.16.2, CVE-2025-23266 fixed in 1.17.8).")
    METHOD = ("Parses /proc/<pid>/cgroup of each GPU process for runtime-specific scope names and records "
              "NVIDIA_VISIBLE_DEVICES; the toolkit version comes from dpkg-query / rpm (allow-listed, read-only).")
    ANALOG = "linux.mountinfo / linux.capabilities"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            raise UnsupportedError(
                "nvidia.containers inspects Linux cgroups and the NVIDIA Container Toolkit, which do not exist on "
                "Windows: GPU containers and WSL2 reach the GPU through Hyper-V GPU paravirtualisation, visible on "
                "the host as vmwp.exe in windows.gpuprocs. Run nvidia.containers inside the Linux guest (WSL2/VM) "
                "and wsl.dxgprocs on a guest memory image")
        require_linux(src, self.NAME)

        def rows():
            ver, how = toolkit_version(src)
            if ver is None:
                yield 0, ("toolkit", na(""), "nvidia-container-toolkit", "", "", how or "not installed", "info")
            else:
                m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver)
                vt = tuple(int(x) for x in m.groups()) if m else None
                yield 0, ("toolkit", na(""), "nvidia-container-toolkit", ver, "", "version via %s" % how, "info")
                for cve, fixed, desc in TOOLKIT_CVES:
                    if vt is None:
                        status, sev = "version unparsable", "unknown"
                    elif vt < fixed:
                        status, sev = "VULNERABLE (fixed in %s)" % ".".join(map(str, fixed)), "high"
                    else:
                        status, sev = "not affected", "info"
                    yield 0, ("cve", na(""), cve, ver, status, desc, sev)
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                p = info["proc"]
                if p is None:
                    continue
                runtime, cid = container_of(p.get("cgroup", ""))
                vis = (p.get("environ") or {}).get("NVIDIA_VISIBLE_DEVICES")
                if runtime or vis:
                    yield 0, ("process", pid, procfs.proc_name(p), runtime or "unknown", cid or na("n/a"),
                              "GPU fds=%d%s" % (len(procfs.gpu_fds(p)),
                                                ", NVIDIA_VISIBLE_DEVICES=%s" % vis if vis else ""), "info")
        return TreeGrid([("Kind", str), ("PID", int), ("Name", str), ("Runtime/Version", str), ("Container/Status", str),
                         ("Details", str), ("Severity", str)], rows())


DAEMONS = [("nvidia-persistenced", "/usr/bin/nvidia-persistenced", ["nvidia-persistenced.service"]),
           ("nv-hostengine", "/usr/bin/nv-hostengine", ["nvidia-dcgm.service", "dcgm.service"]),
           ("nv-fabricmanager", "/usr/bin/nv-fabricmanager", ["nvidia-fabricmanager.service"]),
           ("nvidia-cuda-mps-control", "/usr/bin/nvidia-cuda-mps-control", []),
           ("nvidia-cuda-mps-server", "/usr/bin/nvidia-cuda-mps-server", []),
           ("nvidia-powerd", "/usr/bin/nvidia-powerd", ["nvidia-powerd.service"]),
           ("dcgm-exporter", "/usr/bin/dcgm-exporter", ["dcgm-exporter.service"]),
           ("nvidia-gridd", "/usr/bin/nvidia-gridd", ["nvidia-gridd.service"])]
UNIT_DIRS = ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system")


def _exe_base(p) -> str:
    return procfs.exe_path(p).replace(" (deleted)", "").rsplit("/", 1)[-1]


def matches_daemon(p, name) -> bool:
    argv0 = (p.get("cmdline") or [""])[0].rsplit("/", 1)[-1]
    return p.get("comm") == name[:15] or _exe_base(p) == name or argv0 == name


#: install locations of NVIDIA's Windows binaries (driver store, Program Files, System32 copies)
WIN_NVIDIA_DIRS_RE = re.compile(r"\\program files(?: \(x86\))?\\nvidia corporation\\|"
                                r"\\system32\\driverstore\\filerepository\\nv[^\\]*\.inf_", re.I)
WIN_SYSTEM_DIRS_RE = re.compile(r"^[a-z]:\\windows\\(?:system32|syswow64)\\", re.I)
#: image names of NVIDIA's Windows services and helpers (lower case)
WIN_NVIDIA_BINARIES = {"nvcontainer.exe", "nvdisplay.container.exe", "nvsphelper64.exe", "nvidia share.exe",
                       "nvidia overlay.exe", "nvidia app.exe", "nvidia web helper.exe", "nvtelemetrycontainer.exe",
                       "nvcplui.exe", "nvidia-smi.exe", "nvdebugdump.exe", "nvbackend.exe"}
START_TYPES = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}


def win_nvidia_services(src):
    """``[(service name, values)]`` of NVIDIA services registered under HKLM\\...\\Services: names starting with
    nv/NVIDIA whose DisplayName or ImagePath names NVIDIA or an NVIDIA install folder."""
    out = []
    for name in (src.registry_key(SERVICES_KEY) or {}).get("subkeys", []):
        if not re.match(r"(?i)^nv|nvidia", name):
            continue
        vals = (src.registry_key(SERVICES_KEY + "\\" + name) or {}).get("values") or {}
        text = " ".join(str(vals.get(k) or "") for k in ("DisplayName", "ImagePath", "Description"))
        if "nvidia" in text.lower() or WIN_NVIDIA_DIRS_RE.search(str(vals.get("ImagePath") or "")):
            out.append((name, vals))
    return out


class Daemons(Plugin):
    NAME = "nvidia.daemons"
    CATEGORY = "nvidia.services"
    DESCRIPTION = ("Lists NVIDIA service daemons (persistenced, DCGM hostengine, Fabric Manager, MPS, powerd, "
                   "dcgm-exporter, gridd): whether each runs, from which executable, and which unit files exist.")
    METHOD = ("Matches /proc/<pid>/{comm,exe,cmdline} against the daemon names, compares the executable with the "
              "packaged path, and looks for unit files in /etc/systemd/system, /lib/systemd/system and "
              "/usr/lib/systemd/system. On Windows: the user-mode NVIDIA services registered under "
              "HKLM\\SYSTEM\\CurrentControlSet\\Services (ImagePath, start type, account) matched to running "
              "processes by image path, plus running NVIDIA binaries that are not a service image; the expected "
              "location is Program Files\\NVIDIA Corporation, the driver store or System32.")
    ANALOG = "windows.svcscan / windows.svclist"
    SOURCES = ("live",)

    def _windows(self, src):
        procs = src.win_processes()

        def rows():
            images = set()
            for name, vals in win_nvidia_services(src):
                if not (vals.get("Type") or 0) & 0x30:
                    continue  # kernel drivers: see nvidia.modules / nvidia.driver
                image = wgpu.win_path(src, str(vals.get("ImagePath") or ""))
                images.add(image.lower())
                reg = "%s\\%s (start %s, account %s)" % (SERVICES_KEY, name,
                                                         START_TYPES.get(vals.get("Start"), vals.get("Start")),
                                                         vals.get("ObjectName") or "-")
                expected = bool(WIN_NVIDIA_DIRS_RE.search(image) or WIN_SYSTEM_DIRS_RE.search(image))
                running = [p for p in procs if image and (p.get("path") or "").lower() == image.lower()]
                # a LocalSystem service's image path is not readable without elevation: match it by image name
                unverified = [p for p in procs if image and not p.get("path") and
                              win_name(p).lower() == wgpu.basename(image).lower()]
                images.update("?" + win_name(p).lower() for p in unverified)
                if not running and not unverified:
                    yield 0, (name, False, na(""), image or na("no ImagePath"), expected, reg)
                for p in sorted(running, key=lambda x: x["pid"]):
                    yield 0, (name, True, p["pid"], p["path"], expected, reg)
                for p in sorted(unverified, key=lambda x: x["pid"]):
                    yield 0, (name, True, p["pid"], na("access denied (registered %s)" % image), na("unverified"),
                              reg)
            for p in sorted(procs, key=lambda x: x["pid"]):
                path = p.get("path") or ""
                if path.lower() in images or (not path and "?" + win_name(p).lower() in images):
                    continue
                if WIN_NVIDIA_DIRS_RE.search(path) or (p.get("name") or "").lower() in WIN_NVIDIA_BINARIES:
                    parent = next((q for q in procs if q["pid"] == p.get("ppid")), None)
                    yield 0, (win_name(p), True, p["pid"], path or na("access denied"),
                              bool(WIN_NVIDIA_DIRS_RE.search(path) or WIN_SYSTEM_DIRS_RE.search(path)) if path
                              else na("unknown"),
                              "not a service image (parent %s %s)" % (p.get("ppid"), win_name(parent)))
        return TreeGrid([("Service", str), ("Running", bool), ("PID", int), ("Exe", str), ("Expected path", bool),
                         ("Registration", str)], rows())

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            return self._windows(src)
        require_linux(src, self.NAME)
        procs = all_procs(self.ctx)

        def rows():
            for name, expected, units in DAEMONS:
                running = [(pid, p) for pid, p in sorted(procs.items()) if matches_daemon(p, name)]
                found_units = [d + "/" + u for d in UNIT_DIRS for u in (units or [name + ".service"])
                               if src.stat(d + "/" + u) is not None]
                if not running:
                    if found_units:
                        yield 0, (name, False, na(""), na(""), na(""), ",".join(found_units))
                    continue
                for pid, p in running:
                    exe = procfs.exe_path(p) or ""
                    yield 0, (name, True, pid, exe or na("unreadable"),
                              exe == expected if exe else na("unknown"), ",".join(found_units) or "-")
        return TreeGrid([("Daemon", str), ("Running", bool), ("PID", int), ("Exe", str), ("Expected path", bool),
                         ("Unit files", str)], rows())


CACHE_DIRS = [(".nv/ComputeCache", "CUDA JIT ComputeCache", True), (".nv/GLCache", "NVIDIA GL shader cache (legacy)",
              False), (".cache/nvidia/GLCache", "NVIDIA GL/Vulkan shader cache", False),
              (".cache/nvidia/DXCache", "NVIDIA DX shader cache", False)]
WIN_CACHE_DIRS = [("AppData\\Roaming\\NVIDIA\\ComputeCache", "CUDA JIT ComputeCache", True),
                  ("AppData\\Local\\NVIDIA\\GLCache", "NVIDIA GL/Vulkan shader cache", False),
                  ("AppData\\Local\\NVIDIA\\DXCache", "NVIDIA DX shader cache", False)]
WIN_NON_USER_PROFILES = {"public", "default", "default user", "all users", "desktop.ini"}
PROFILE_LIST_KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


def analyse_blob(data: bytes):
    """Find CUDA code in a cache file: returns ``(content_kinds, kernel_names)``."""
    kinds, kernels = [], []
    pos = data.find(b"\x7fELF")
    while pos != -1:
        if len(data) >= pos + 20 and struct.unpack_from("<H", data, pos + 18)[0] == cubin_fmt.EM_CUDA:
            size = elf_extent(data[pos:]) or len(data) - pos
            try:
                c = cubin_fmt.parse_cubin(data[pos:pos + size])
                kinds.append("cubin %s" % c.arch)
                kernels += c.kernel_names()
            except Exception:
                kinds.append("cubin (unparsable)")
        pos = data.find(b"\x7fELF", pos + 1)
    fpos = data.find(fatbin_fmt.FATBIN_MAGIC_BYTES)
    if fpos != -1:
        fb = fatbin_fmt.parse_fatbin(data[fpos:], fpos)
        if fb:
            kinds.append("fatbin (%d entries)" % len(fb.entries))
            for e in fb.entries:
                if e.kind == fatbin_fmt.KIND_PTX and e.data:
                    kernels += ptx_fmt.parse(e.data.split(b"\x00", 1)[0]).entries
                elif e.kind == fatbin_fmt.KIND_ELF and e.data:
                    try:
                        kernels += cubin_fmt.parse_cubin(e.data).kernel_names()
                    except Exception:
                        pass
    m = ptx_fmt.VERSION_RE.search(data)
    if m:
        span = ptx_fmt.carve(data, m.start())
        if span:
            mod = ptx_fmt.parse(data[span[0]:span[1]])
            if mod.entries or mod.target:
                kinds.append("ptx %s" % (mod.target or "?"))
                kernels += mod.entries
    return kinds, sorted(set(kernels))


class ComputeCache(Plugin, TimeLinerInterface):
    NAME = "nvidia.computecache"
    CATEGORY = "nvidia.artifacts"
    DESCRIPTION = ("Lists NVIDIA JIT and shader cache entries for every user (CUDA ComputeCache, GL/Vulkan/DX "
                   "shader caches): file times show when GPU code ran, and kernels found inside identify what ran "
                   "(e.g. mining kernels).")
    METHOD = ("Walks ~/.nv/ComputeCache, ~/.nv/GLCache, ~/.cache/nvidia/{GLCache,DXCache} under /root and /home/*; "
              "ComputeCache files are scanned for cubins (EM_CUDA ELF), fatbins (0xBA55ED50) and PTX (.version) "
              "and kernel names are classified with the miner/cracker indicators. On Windows the same caches are "
              "AppData\\Roaming\\NVIDIA\\ComputeCache and AppData\\Local\\NVIDIA\\{GLCache,DXCache} of every "
              "profile under the ProfileList ProfilesDirectory (C:\\Users); profiles this account cannot read are "
              "reported as such.")
    ANALOG = "windows.shimcachemem / windows.registry.amcache"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("max_files", int, 500, "maximum cache files to examine"),
                    Requirement("read_bytes", "size", 256 * 1024, "bytes read from each ComputeCache file")]

    def _homes(self, src):
        """``(home directories, path separator, cache dirs)`` of the analysed system."""
        if src.is_windows:
            vals = (src.registry_key(PROFILE_LIST_KEY) or {}).get("values") or {}
            root = str(vals.get("ProfilesDirectory") or r"C:\Users").rstrip("\\")
            users = [n for n in (src.listdir(root) or []) if n.lower() not in WIN_NON_USER_PROFILES]
            return [root + "\\" + n for n in users], "\\", WIN_CACHE_DIRS
        return ["/root"] + ["/home/" + n for n in (src.listdir("/home") or [])], "/", CACHE_DIRS

    def _entries(self):
        """``(label, path, stat, kinds, kernels)``; stat None: profile unreadable; kinds None: not in snapshot."""
        src = self.ctx.live
        homes, sep, cache_dirs = self._homes(src)
        budget = self.opts["max_files"]
        for home in homes:
            if sep == "\\" and src.listdir(home) is None:
                yield "user profile", home, None, [], []
                continue
            for rel, label, analyse in cache_dirs:
                root = home + sep + rel
                stack = [(root, 0)]
                while stack and budget > 0:
                    d, depth = stack.pop()
                    names = src.listdir(d)
                    if names is None:
                        continue
                    for n in names:
                        path = d + sep + n
                        st = src.stat(path)
                        if st is None:
                            continue
                        if st["is_dir"]:
                            if depth < 8:
                                stack.append((path, depth + 1))
                            continue
                        budget -= 1
                        kinds, kernels = ([], [])
                        if analyse and st["size"]:
                            try:
                                data = src.read_bytes(path, self.opts["read_bytes"]) or b""
                                kinds, kernels = analyse_blob(data)
                            except NotRecordedError:
                                kinds = None
                        yield label, path, st, kinds, kernels
                        if budget <= 0:
                            break

    def run(self):
        src = self.ctx.live
        if not src.is_windows:
            require_linux(src, self.NAME)

        def rows():
            for label, path, st, kinds, kernels in self._entries():
                if st is None:
                    yield 0, (label, path, na(""), na(""), na("profile not readable by this account (run as "
                                                              "Administrator)"), na(""), na(""))
                    continue
                if kinds is None:
                    nr = na("not recorded in snapshot (--read-bytes differs from the acquisition)")
                    yield 0, (label, path, st["size"], utc_from_epoch(st.get("mtime")), nr, nr, nr)
                    continue
                inds = sorted({"%s:%s" % c for k in kernels for c in miners.classify(k, context="kernel")})
                yield 0, (label, path, st["size"], utc_from_epoch(st.get("mtime")), ", ".join(kinds) or "-",
                          ", ".join(kernels) or "-", ", ".join(inds) or "-")
        return TreeGrid([("Cache", str), ("Path", str), ("Size", int), ("Modified", object), ("Content", str),
                         ("Kernels", str), ("Indicators", str)], rows())

    def generate_timeline(self):
        for label, path, st, kinds, kernels in self._entries():
            if st is None:
                continue
            yield ("%s entry %s modified%s" % (label, path, (" (kernels: %s)" % ", ".join(kernels)) if kernels else ""),
                   "Modified", utc_from_epoch(st.get("mtime")))


VULKAN_DIRS = [("/usr/share/vulkan/icd.d", "vulkan-icd"), ("/etc/vulkan/icd.d", "vulkan-icd"),
               ("/usr/share/vulkan/implicit_layer.d", "vulkan-implicit-layer"),
               ("/etc/vulkan/implicit_layer.d", "vulkan-implicit-layer"),
               ("/usr/share/vulkan/explicit_layer.d", "vulkan-explicit-layer"),
               ("/etc/vulkan/explicit_layer.d", "vulkan-explicit-layer"),
               ("/usr/share/glvnd/egl_vendor.d", "egl-vendor"), ("/etc/glvnd/egl_vendor.d", "egl-vendor")]


def _json_libraries(text: str):
    try:
        doc = json.loads(text)
    except ValueError:
        return [("(invalid JSON)", "")]
    out = []
    items = []
    for key in ("ICD", "layer"):
        if isinstance(doc.get(key), dict):
            items.append(doc[key])
    items += [x for x in doc.get("layers", []) if isinstance(x, dict)]
    for it in items:
        out.append((it.get("name", ""), it.get("library_path", "")))
    return out


class Autostart(Plugin):
    NAME = "nvidia.autostart"
    CATEGORY = "nvidia.services"
    DESCRIPTION = ("Lists configuration that makes code load into GPU applications or run with the NVIDIA "
                   "driver: OpenCL ICDs, Vulkan ICDs and implicit/explicit layers, EGL vendors, /etc/ld.so.preload, "
                   "modprobe install hooks, udev rules and systemd units; flags libraries in user-writable or "
                   "temporary locations and missing files.")
    METHOD = ("Reads /etc/OpenCL/vendors/*.icd, the Vulkan/EGL JSON manifests (ICD.library_path, layer.library_path), "
              "~/.local/share/vulkan/implicit_layer.d, /etc/ld.so.preload, modprobe.d, udev rules and NVIDIA "
              "systemd units. Implicit Vulkan layers load into every Vulkan application. On Windows: "
              "HKLM/HKLM WOW6432Node/HKCU SOFTWARE\\Khronos\\OpenCL\\Vendors and Khronos\\Vulkan\\{Drivers,"
              "ImplicitLayers,ExplicitLayers} (each manifest's library_path resolved), and the OpenCL*/Vulkan* "
              "driver names of every display-class adapter key.")
    ANALOG = "windows.registry.scheduled_tasks / windows.svcscan (persistence)"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("suspicious_only", bool, False, "only suspicious entries")]

    def _entries(self):
        src = self.ctx.live
        for path in src.glob_dir("/etc/OpenCL/vendors", r"\.icd$"):
            lib = (src.read_text(path) or "").strip()
            yield ("opencl-icd", path, lib) + path_risk(src, lib)
        homes = ["/root"] + ["/home/" + n for n in (src.listdir("/home") or [])]
        dirs = list(VULKAN_DIRS) + [(h + "/.local/share/vulkan/implicit_layer.d", "vulkan-implicit-layer (user)")
                                    for h in homes]
        for d, kind in dirs:
            for path in src.glob_dir(d, r"\.json$"):
                for name, lib in _json_libraries(src.read_text(path) or ""):
                    sus, why = path_risk(src, lib)
                    yield (kind, path, "%s %s" % (name, lib) if name else lib, sus, why)
        pre = src.read_text("/etc/ld.so.preload")
        if pre is not None:
            for lib in pre.split():
                sus, why = path_risk(src, lib)
                yield ("ld.so.preload", "/etc/ld.so.preload", lib, True,
                       "global preload into every dynamically linked process" + ("; " + why if why else ""))
        for e in modprobe_entries(src):
            if "nvidia" not in e["module"] and "nvidia" not in e["line"]:
                continue
            if e["kind"] == "install":
                yield ("modprobe-install", e["file"], e["line"], True, "runs a command when the module is loaded")
            elif e["kind"] == "options":
                yield ("modprobe-options", e["file"], "%s %s=%s" % (e["module"], e["key"], e["value"]), False, "")
            else:
                yield ("modprobe-" + e["kind"], e["file"], e["line"], False, "")
        for d in ("/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"):
            for path in src.glob_dir(d, r"\.rules$"):
                for line in (src.read_text(path) or "").splitlines():
                    if "nvidia" in line.lower() and "RUN" in line:
                        m = re.search(r'RUN\+?="([^"]+)"', line)
                        cmd = m.group(1) if m else line.strip()
                        sus, why = path_risk(src, cmd.split()[0] if cmd else "")
                        yield ("udev", path, cmd, sus, why)
        for d in UNIT_DIRS:
            for path in src.glob_dir(d, r"(nvidia|nv-|dcgm|cuda)"):
                for line in (src.read_text(path) or "").splitlines():
                    if line.startswith(("ExecStart", "ExecStartPre", "ExecStartPost")):
                        cmd = line.split("=", 1)[1].strip().lstrip("-@+!")
                        sus, why = path_risk(src, cmd.split()[0] if cmd else "")
                        yield ("systemd", path, cmd, sus, why)

    def _manifest(self, src, kind, manifest, note=""):
        """Rows for one Vulkan JSON manifest: the manifest itself and the library each entry loads."""
        msus, mwhy = win_path_risk(src, manifest)
        text = src.read_text(manifest) if not mwhy.startswith("referenced") else None
        if text is None:
            yield (kind, manifest, "(manifest)", msus or True, mwhy or "manifest unreadable")
            return
        for name, lib in _json_libraries(text):
            resolved = lib
            if lib and ("\\" in lib or "/" in lib) and not ntpath.isabs(lib):
                resolved = ntpath.normpath(ntpath.join(ntpath.dirname(manifest), lib))
            lsus, lwhy = win_path_risk(src, resolved)
            why = "; ".join(w for w in (("manifest: " + mwhy) if mwhy else "", lwhy, note) if w)
            yield (kind, manifest, "%s %s" % (name, resolved) if name else resolved, msus or lsus, why)

    def _windows_entries(self):
        src = self.ctx.live
        for hive, label in (("HKLM\\SOFTWARE", ""), ("HKLM\\SOFTWARE\\WOW6432Node", " (32-bit)"),
                            ("HKCU\\SOFTWARE", " (user)")):
            vendors = hive + "\\Khronos\\OpenCL\\Vendors"
            for dll, state in sorted(((src.registry_key(vendors) or {}).get("values") or {}).items()):
                sus, why = win_path_risk(src, dll)
                yield ("opencl-icd" + label, vendors, dll, sus,
                       "; ".join(w for w in (why, "disabled (value %s)" % state if state else "") if w))
            for sub, kind in (("Drivers", "vulkan-icd"), ("ImplicitLayers", "vulkan-implicit-layer"),
                              ("ExplicitLayers", "vulkan-explicit-layer")):
                key = hive + "\\Khronos\\Vulkan\\" + sub
                for manifest, state in sorted(((src.registry_key(key) or {}).get("values") or {}).items()):
                    for row in self._manifest(src, kind + label, manifest,
                                              "disabled (value %s)" % state if state else ""):
                        yield row
        for key, vals in display_adapter_keys(src):
            for name in sorted(vals):
                if not name.startswith(("OpenCL", "Vulkan")) or "DriverName" not in name and "Layers" not in name:
                    continue
                for path in (vals[name] if isinstance(vals[name], list) else [vals[name]]):
                    if not isinstance(path, str) or not path:
                        continue
                    kind = "display-driver %s (%s)" % (name, vals.get("DriverDesc") or key.rsplit("\\", 1)[-1])
                    if path.lower().endswith(".json"):
                        for row in self._manifest(src, kind, path):
                            yield row
                    else:
                        sus, why = win_path_risk(src, path)
                        yield (kind, key, path, sus, why)

    def run(self):
        src = self.ctx.live
        if src.is_windows:
            entries = self._windows_entries()
        else:
            require_linux(src, self.NAME)
            entries = self._entries()

        def rows():
            for kind, source, entry, sus, why in entries:
                if self.opts["suspicious_only"] and not sus:
                    continue
                yield 0, (kind, source, entry, sus, why)
        return TreeGrid([("Kind", str), ("Source", str), ("Entry", str), ("Suspicious", bool), ("Reason", str)],
                        rows())
