"""GPU kernels that NVIDIA's own driver loads into every CUDA process.

Observed on driver 592.82 (CUDA 13.1, Ada, WSL2): libcuda unpacks these internal
modules into the process heap (copy/fill kernels, compute-preemption trap
handlers, device-side syscall trampolines, CUDA graph schedulers). They look
exactly like a runtime-loaded payload, so without attribution every CUDA process
would be flagged.

Name matching is WEAK (an attacker can reuse a name); ``--baseline`` hash
matching from a known-clean process on the same driver version is STRONG.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Iterable, Optional

_PATTERNS = [
    # copy / fill engines implemented as kernels
    r"(memcpy|memset)\w*",
    r"(Char|Short|Int)Aligned_\w+",
    # compiler / device-runtime support routines
    r"__cuda_(sm\w+|syscall\w*)",
    r"_Z\d+__cuda_(sm\w+|syscall\w*)",  # the same routines, C++-mangled (e.g. _Z28__cuda_syscall_bw_tld_shared...)
    r"syscall_(no_stack_switch_)?trampoline_\w+",
    r"_ZN\d+_INTERNAL_[0-9a-f]+_\d+_(opencl_)?syscall_device_shared_cu_[\w$]+",
    r"_Z\d+(Free|Malloc)Internal[\w$]*",
    r"_Z\d+(cnp|cnpv2|CNP|cmdQueue|cnpv2CmdQueue)[\w$]*",
    r"(vfprintf_internal|vfprintf|vprintf|malloc|free|__assertfail|__profile)",
    # CUDA Dynamic Parallelism (CNP) device runtime and device-side runtime API stubs
    r"cnp\w+",
    r"cuda(Graph|Device|Stream|Event|Malloc|Free|Get|Set|Launch|Func|Peek|Occupancy|Memcpy|Memset|Runtime|"
    r"Subgrid|Fabric)\w*",  # Subgrid*/Fabric* seen in every CUDA process on driver 610.91 (WSL2 and Windows)
    # CUDA graph / fork-join schedulers
    r"(ampereForkScheduler|conditionalScheduler|deviceGraphScheduler|forkJoinScheduler|exitfunction)",
    r"(cg_entry|tex_entry|entry_exit|generic_entry)",
    # compute-instruction-level preemption (CILP) trap handlers and helpers
    r"(cilp_)?trap_?handler(_(save|restore))?",
    r"do_(preempt_(save|restore)|read_trap_reason|set_defer_continuations)",
    r"get_defer_continuation_state_and_clear",
    r"(do_)?(detect_continuation|handle_continuations?|pause|pause_quiet)",
    r"membar_war_bug\d+",
]
_RX = re.compile(r"^(?:%s)$" % "|".join(_PATTERNS))


#: NVIDIA user-mode driver libraries that carry GPU kernels of their own (CUDA, OpenCL, video decode/encode,
#: D3D/Vulkan/OpenGL user-mode drivers, OptiX, DLSS/NGX, AI video effects...): Windows DLL and Linux/WSL .so names
NVIDIA_LIBRARY_RE = re.compile(
    r"(?i)(?:^|[\\/])(?:lib)?(?:nvcuda|cuda|nvopencl|nvidia-opencl|nvcuvid|nvidia-encode|nvencodeapi|nvd3dum|"
    r"nvwgf2um|nvdxdlkernels|nvoptix|nvidia-rtcore|nvdirectsr|nvppex|nvpresent|nvngx|nvai\w*|nvdlpp\w*|nvoglv|"
    r"nvidia-glcore|nvidia-eglcore|nvidia-gpucomp|nvidia-ptxjitcompiler|nvptxjitcompiler|nvidia-nvvm|nvvm|"
    r"nvoptix|nvldumd|nvgpucomp|nvrtc)[\w.\-]*\.(?:dll|so(?:\.\d+)*)$")


def is_nvidia_library(path: str) -> bool:
    """True for the on-disk path of an NVIDIA user-mode driver library (whose embedded kernels are driver code)."""
    return bool(path) and bool(NVIDIA_LIBRARY_RE.search(path.replace(" (deleted)", "")))


def is_driver_internal(name: str) -> bool:
    return bool(_RX.match(name))


def all_driver_internal(names: Iterable[str]) -> bool:
    names = [n for n in names if n]
    return bool(names) and all(is_driver_internal(n) for n in names)


class Baseline:
    """SHA-256 of kernel machine code known to be legitimate on this host/driver."""

    def __init__(self, hashes: Optional[Dict[str, str]] = None, meta: Optional[dict] = None):
        self.hashes = dict(hashes or {})
        self.meta = dict(meta or {})

    @classmethod
    def load(cls, path: str) -> "Baseline":
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if doc.get("format") != "keto-kernel-baseline/1":
            raise ValueError("not a Keto kernel baseline")
        return cls(doc.get("kernels", {}), doc.get("meta", {}))

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"format": "keto-kernel-baseline/1", "meta": self.meta, "kernels": self.hashes}, fh,
                      indent=1, sort_keys=True)

    def covers(self, hashes: Iterable[str]) -> bool:
        hashes = list(hashes)
        return bool(hashes) and all(h in self.hashes for h in hashes)
