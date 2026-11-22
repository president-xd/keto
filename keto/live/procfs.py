"""Helpers that turn raw ``/proc`` records into GPU-forensics facts."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

GPU_DEVICE_RE = re.compile(r"^/dev/(nvidiactl|nvidia\d+|nvidia-uvm|nvidia-uvm-tools|nvidia-modeset|nvidia-caps/\S+|"
                           r"nvidia-nvswitch\S*|nvidia-nvlink|dxg|dri/card\d+|dri/renderD\d+)$")
NVIDIA_DEVICE_RE = re.compile(r"^/dev/(nvidia\S*|dxg)$")
GPU_LIB_RE = re.compile(
    r"/(lib(?:cuda|nvidia-[\w.+-]+|nvcuvid|cudart|cublas\w*|cudnn\w*|cufft\w*|curand\w*|cusparse\w*|cusolver\w*|"
    r"nvrtc\w*|nvJitLink\w*|nccl\w*|nvToolsExt\w*|cupti\w*|cudadebugger|nvoptix\w*|dxcore|d3d12\w*|nvwgf2umx|"
    r"nvdxdlkernels|OpenCL|vulkan|GLX_nvidia|EGL_nvidia|nvcuda|nvidia-ml)(?:[\w.+-]*)\.so[\w.]*)(?: \(deleted\))?$")
CAPTURE_LIBS = ("libnvidia-fbc", "libnvidia-ifr", "libnvfbc", "libnvidia-encode")
DEBUG_LIBS = ("libcudadebugger",)
PROFILER_LIBS = ("libcupti", "libnvperf", "libnvToolsExt", "libnvtx")
RUNTIME_LIBS = ("libcuda.so", "libcudart", "libnvidia-ml", "libnvcuda", "libdxcore", "libOpenCL", "libvulkan",
                "libnvidia-opencl", "libGLX_nvidia", "libEGL_nvidia", "libnvoptix", "libnvcuvid", "libnvidia-encode")


def gpu_fds(proc: dict) -> List[list]:
    return [fd for fd in proc.get("fds", []) if GPU_DEVICE_RE.match(fd[1])]


def gpu_libs(proc: dict) -> List[dict]:
    seen: Dict[str, dict] = {}
    for m in proc.get("maps", []):
        path = m.get("path", "")
        if not GPU_LIB_RE.search(path):
            continue
        e = seen.setdefault(path, {"path": path, "base": m["start"], "end": m["end"], "perms": set(),
                                   "deleted": path.endswith("(deleted)")})
        e["base"] = min(e["base"], m["start"])
        e["end"] = max(e["end"], m["end"])
        e["perms"].add(m["perms"])
    out = []
    for e in seen.values():
        e["perms"] = ",".join(sorted(e["perms"]))
        out.append(e)
    return sorted(out, key=lambda e: e["base"])


def lib_basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].replace(" (deleted)", "")


def has_lib(proc: dict, prefixes) -> List[str]:
    return sorted({lib_basename(l["path"]) for l in gpu_libs(proc) if lib_basename(l["path"]).startswith(prefixes)}
                  | {lib_basename(m["path"]) for m in proc.get("maps", [])
                     if lib_basename(m.get("path", "")).startswith(prefixes)})


def nvml_pids(nvml: dict) -> Dict[int, Set[str]]:
    out: Dict[int, Set[str]] = {}
    for dev in nvml.get("devices", []):
        for key, label in (("compute_processes", "nvml-compute"), ("graphics_processes", "nvml-graphics"),
                           ("mps_compute_processes", "nvml-mps")):
            procs = dev.get(key)
            if isinstance(procs, list):
                for p in procs:
                    out.setdefault(p["pid"], set()).add("%s:gpu%d" % (label, dev.get("index", 0)))
    return out


def gpu_processes(source, include_nvml: bool = True) -> Dict[int, dict]:
    """Every process with evidence of GPU use: NVML process lists, open GPU device
    nodes, or GPU runtime libraries mapped. Returns ``pid -> {proc, evidence}``. The Keto process itself is
    left out: loading NVML/CUDA to answer the query opens GPU device nodes, which is not evidence."""
    result: Dict[int, dict] = {}
    nv = nvml_pids(source.nvml()) if include_nvml else {}
    self_pid = (source.platform() or {}).get("self_pid")
    for pid in source.pids():
        if pid == self_pid:
            continue
        p = source.proc(pid)
        if p is None:
            continue
        ev: Set[str] = set(nv.get(pid, set()))
        for fd, target in gpu_fds(p):
            ev.add("fd:" + target)
        for lib in has_lib(p, RUNTIME_LIBS):
            ev.add("lib:" + lib)
        if ev:
            result[pid] = {"proc": p, "evidence": ev}
    for pid, labels in nv.items():
        if pid not in result and pid != self_pid:
            result[pid] = {"proc": None, "evidence": set(labels) | {"not-in-procfs"}}
    return result


def proc_name(proc: Optional[dict]) -> str:
    if not proc:
        return "?"
    return proc.get("comm") or (proc.get("cmdline") or ["?"])[0]


def exe_path(proc: Optional[dict]) -> str:
    return (proc or {}).get("exe") or ""
