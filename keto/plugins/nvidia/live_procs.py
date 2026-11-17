"""Live (or snapshot) GPU process analysis."""

from __future__ import annotations

import json
import re
import struct

from keto.formats import cubin as cubin_fmt
from keto.formats import fatbin as fatbin_fmt
from keto.formats import ptx as ptx_fmt
from keto.formats.elf import elf_extent
from keto.framework.exceptions import UnsupportedError
from keto.framework.plugin import Plugin, Requirement, TimeLinerInterface
from keto.framework.treegrid import Address, TreeGrid, na
from keto.framework.util import utc_from_epoch
from keto.indicators import miners
from keto.live import procfs


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
              "libraries (/proc/<pid>/maps). NVML PIDs absent from /proc are kept and marked.")
    ANALOG = "windows.pslist / linux.pslist"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def _procs(self):
        return procfs.gpu_processes(self.ctx.live)

    def run(self):
        src = self.ctx.live
        nv = src.nvml()

        def rows():
            for pid, info in sorted(self._procs().items()):
                if self.opts["pid"] is not None and pid != self.opts["pid"]:
                    continue
                p = info["proc"]
                yield 0, (pid, p["ppid"] if p else na("not in /proc"), procfs.proc_name(p),
                          p["uid"] if p else na(""), utc_from_epoch(p["start_time"]) if p and p["start_time"]
                          else na("unknown"), _gpu_memory(nv, pid), ",".join(sorted(info["evidence"])),
                          procfs.exe_path(p) or na("unreadable"))
        return TreeGrid([("PID", int), ("PPID", int), ("Name", str), ("UID", int), ("Started", object),
                         ("GPU Memory", int), ("Evidence", str), ("Exe", str)], rows())

    def generate_timeline(self):
        for pid, info in self._procs().items():
            p = info["proc"]
            if p and p.get("start_time"):
                yield ("GPU process %s (%d) started" % (procfs.proc_name(p), pid), "Created",
                       utc_from_epoch(p["start_time"]))


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


def env_finding(key: str, value: str):
    """``(suspicious, reason)`` for one environment variable of a GPU process."""
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
              "/proc/<pid>/status upwards; ancestors without GPU evidence are included and marked GPU=False.")
    ANALOG = "windows.pstree / linux.pstree"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
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
    METHOD = "Reads /proc/<pid>/cmdline (NUL-separated argv) and the /proc/<pid>/exe link for each nvidia.pslist PID."
    ANALOG = "windows.cmdline / linux.psaux"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def run(self):
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
              "settings are reported as context.")
    ANALOG = "windows.envars / linux.envars"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"),
                    Requirement("suspicious_only", bool, False, "only suspicious variables"),
                    Requirement("all", bool, False, "also show retained variables with no finding (PATH, HOME...)")]

    def run(self):
        def rows():
            for pid, info in sorted(gpu_procs(self.ctx).items()):
                p = info["proc"]
                if not pid_filter(self.opts, pid) or p is None:
                    continue
                env = p.get("environ")
                if env is None:
                    if not self.opts["suspicious_only"]:
                        yield 0, (pid, procfs.proc_name(p), na("environ unreadable (permission)"), na(""), False, "")
                    continue
                for k in sorted(env):
                    sus, reason = env_finding(k, env[k])
                    if self.opts["suspicious_only"] and not sus:
                        continue
                    if not reason and not self.opts["all"]:
                        continue
                    yield 0, (pid, procfs.proc_name(p), k, env[k], sus, reason)
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
    DESCRIPTION = "Lists every open GPU device-node file descriptor per process (control, GPU, UVM, modeset, caps, dxg)."
    METHOD = ("Resolves each /proc/<pid>/fd/<n> symlink and keeps targets matching /dev/nvidia*, /dev/nvidia-caps/*, "
              "/dev/dxg and DRM nodes; the node type tells what the process can do (e.g. nvidia-uvm-tools = event "
              "tracing, nvidiactl = RM object allocation).")
    ANALOG = "windows.handles / linux.lsof"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID")]

    def run(self):
        require_linux(self.ctx.live, self.NAME)

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
              "/tmp, /var/tmp, /dev/shm, /run/user, memfd: or marked '(deleted)' are flagged.")
    ANALOG = "windows.dlllist / linux.library_list"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("pid", int, None, "only this PID"),
                    Requirement("all_libs", bool, False, "list every file-backed mapping, not only GPU/suspicious ones")]

    def run(self):
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
        return TreeGrid([("PID", int), ("Name", str), ("Base", Address), ("End", Address), ("Perms", str),
                         ("Path", str), ("GPU library", bool), ("Suspicious", bool), ("Reason", str)], rows())


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


class Debugger(Plugin):
    NAME = "nvidia.debugger"
    CATEGORY = "nvidia.processes"
    DESCRIPTION = ("Finds GPU debugging activity: processes with the CUDA debugger backend loaded, GPU processes "
                   "ptrace-attached by another process, and running GPU debugger/profiler tools.")
    METHOD = ("Looks for libcudadebugger.so in /proc/<pid>/maps, TracerPid in /proc/<pid>/status for GPU "
              "processes, tool names (cuda-gdb, nsys, ncu, compute-sanitizer...) in comm/exe, and CUDA debugger "
              "environment settings.")
    ANALOG = "windows.debugregisters / linux.ptrace"
    SOURCES = ("live",)

    def run(self):
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
              "/dev/nvidia-uvm-tools and injection variables.")
    ANALOG = "linux.tracing.perf_events"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
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
        return TreeGrid([("Scope", str), ("PID", int), ("Name/Source", str), ("Indicator", str), ("Details", str),
                         ("Risk", str)], rows())


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


class Daemons(Plugin):
    NAME = "nvidia.daemons"
    CATEGORY = "nvidia.services"
    DESCRIPTION = ("Lists NVIDIA service daemons (persistenced, DCGM hostengine, Fabric Manager, MPS, powerd, "
                   "dcgm-exporter, gridd): whether each runs, from which executable, and which unit files exist.")
    METHOD = ("Matches /proc/<pid>/{comm,exe,cmdline} against the daemon names, compares the executable with the "
              "packaged path, and looks for unit files in /etc/systemd/system, /lib/systemd/system and "
              "/usr/lib/systemd/system.")
    ANALOG = "windows.svcscan / windows.svclist"
    SOURCES = ("live",)

    def run(self):
        src = self.ctx.live
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
              "and kernel names are classified with the miner/cracker indicators.")
    ANALOG = "windows.shimcachemem / windows.registry.amcache"
    SOURCES = ("live",)
    REQUIREMENTS = [Requirement("max_files", int, 500, "maximum cache files to examine"),
                    Requirement("read_bytes", "size", 256 * 1024, "bytes read from each ComputeCache file")]

    def _entries(self):
        src = self.ctx.live
        homes = ["/root"] + ["/home/" + n for n in (src.listdir("/home") or [])]
        budget = self.opts["max_files"]
        for home in homes:
            for rel, label, analyse in CACHE_DIRS:
                root = home + "/" + rel
                stack = [(root, 0)]
                while stack and budget > 0:
                    d, depth = stack.pop()
                    names = src.listdir(d)
                    if names is None:
                        continue
                    for n in names:
                        path = d + "/" + n
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
                            data = src.read_bytes(path, self.opts["read_bytes"]) or b""
                            kinds, kernels = analyse_blob(data)
                        yield label, path, st, kinds, kernels
                        if budget <= 0:
                            break

    def run(self):
        require_linux(self.ctx.live, self.NAME)

        def rows():
            for label, path, st, kinds, kernels in self._entries():
                inds = sorted({"%s:%s" % c for k in kernels for c in miners.classify(k)})
                yield 0, (label, path, st["size"], utc_from_epoch(st.get("mtime")), ", ".join(kinds) or "-",
                          ", ".join(kernels) or "-", ", ".join(inds) or "-")
        return TreeGrid([("Cache", str), ("Path", str), ("Size", int), ("Modified", object), ("Content", str),
                         ("Kernels", str), ("Indicators", str)], rows())

    def generate_timeline(self):
        for label, path, st, kinds, kernels in self._entries():
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
              "systemd units. Implicit Vulkan layers load into every Vulkan application.")
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

    def run(self):
        require_linux(self.ctx.live, self.NAME)

        def rows():
            for kind, source, entry, sus, why in self._entries():
                if self.opts["suspicious_only"] and not sus:
                    continue
                yield 0, (kind, source, entry, sus, why)
        return TreeGrid([("Kind", str), ("Source", str), ("Entry", str), ("Suspicious", bool), ("Reason", str)],
                        rows())
