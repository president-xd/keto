"""GPU-related environment variables in any memory image (process dumps, host RAM, VRAM)."""

from __future__ import annotations

import re

from keto.framework.plugin import Plugin, Requirement
from keto.framework.scanners import AnchoredScanner, scan
from keto.framework.treegrid import Address, TreeGrid

# (variable, severity, meaning)
VARIABLES = [
    ("CUDA_INJECTION64_PATH", "high", "library injected into every CUDA process (profiler/injection hook)"),
    ("CUDA_INJECTION32_PATH", "high", "library injected into every 32-bit CUDA process"),
    ("NVTX_INJECTION64_PATH", "high", "library injected through the NVTX tools hook"),
    ("NVTX_INJECTION32_PATH", "high", "library injected through the NVTX tools hook (32-bit)"),
    ("LD_PRELOAD", "medium", "shared objects preloaded into the process (Linux)"),
    ("LD_AUDIT", "medium", "rtld audit library (Linux)"),
    ("CUDA_CACHE_DISABLE", "medium", "CUDA JIT cache disabled (no ComputeCache trace)"),
    ("CUDA_CACHE_PATH", "medium", "CUDA JIT cache relocated"),
    ("CUDA_CACHE_MAXSIZE", "low", "CUDA JIT cache size changed"),
    ("__GL_SHADER_DISK_CACHE", "low", "NVIDIA OpenGL shader cache switch"),
    ("__GL_SHADER_DISK_CACHE_PATH", "low", "NVIDIA OpenGL shader cache relocated"),
    ("CUDA_VISIBLE_DEVICES", "info", "GPU selection"),
    ("NVIDIA_VISIBLE_DEVICES", "info", "container GPU exposure"),
    ("CUDA_ENABLE_COREDUMP_ON_EXCEPTION", "low", "GPU core dumps enabled"),
    ("OCL_ICD_FILENAMES", "medium", "OpenCL ICD loader told to load specific drivers"),
    ("OCL_ICD_VENDORS", "medium", "OpenCL ICD vendor directory overridden"),
    ("VK_ICD_FILENAMES", "medium", "Vulkan driver (ICD) overridden"),
    ("VK_INSTANCE_LAYERS", "medium", "Vulkan layers forced into every Vulkan process"),
    ("VK_LAYER_PATH", "medium", "Vulkan layer search path overridden"),
]
_SEV = {n: (s, why) for n, s, why in VARIABLES}
#: hooks that load a library into the process: severity follows where the library lives, as in
#: nvidia.malware.injection (high from a temporary / user-writable location, medium otherwise)
INJECTION_HOOKS = {"CUDA_INJECTION64_PATH", "CUDA_INJECTION32_PATH", "NVTX_INJECTION64_PATH", "NVTX_INJECTION32_PATH",
                   "LD_PRELOAD", "LD_AUDIT"}
RISKY_PATH = re.compile(r"(?:^|[\s:;])(?:/tmp/|/var/tmp/|/dev/shm/|/run/user/|/home/|/root/|memfd:)"
                        r"|\\(?:appdata\\(?:local|locallow|roaming)|windows\\temp|temp|tmp|downloads|users\\public|"
                        r"programdata|desktop)\\", re.I)


def severity(name: str, value: str) -> str:
    sev = _SEV[name][0]
    if not value:
        return "info"
    if name in INJECTION_HOOKS:
        return "high" if RISKY_PATH.search(value) else "medium"
    return sev
PREFIXES = (b"CUDA_", b"NVTX_", b"LD_PRELOAD", b"LD_AUDIT", b"__GL_", b"NVIDIA_VIS", b"OCL_ICD", b"VK_")
assert all(any(n.encode().startswith(p) for p in PREFIXES) for n, _, _ in VARIABLES)
_NAMES = "|".join(re.escape(n) for n, _, _ in VARIABLES)
ASCII_RE = re.compile(rb"(?<![\w])(" + _NAMES.encode() + rb")=([\x20-\x7e]{0,1024}?)(?=[\x00\n\r])")
UTF16_RE = re.compile(rb"(?<![\w]\x00)((?:" + b"|".join(b"".join(bytes([c, 0]) for c in n.encode())
                                                          for n, _, _ in VARIABLES) +
                      rb"))=\x00((?:[\x20-\x7e]\x00){0,1024}?)(?=\x00\x00)")


class EnvScan(Plugin):
    NAME = "nvidia.envscan"
    CATEGORY = "nvidia.malware"
    DESCRIPTION = ("Finds GPU-related injection and loader variables (CUDA/NVTX injection paths, LD_PRELOAD, CUDA "
                   "cache disabling or relocation, OpenCL/Vulkan ICD and layer overrides) in any memory image: "
                   "process environment blocks in process dumps and host RAM (ASCII on Linux, UTF-16 on Windows), "
                   "and stray copies in VRAM.")
    METHOD = ("Literal anchors for each variable name (ASCII and UTF-16LE), then a regex for NAME=value terminated "
              "by NUL/newline; deduplicated by value. Injection hooks (CUDA/NVTX injection paths, LD_PRELOAD, "
              "LD_AUDIT) are high when the library lives in a temporary or user-writable location, else medium "
              "(the same rule as nvidia.malware.injection).")
    ANALOG = "windows.envars / linux.envars (from raw memory)"
    REQUIREMENTS = [Requirement("all", bool, False, "also report every occurrence, not one per (variable, value)")]

    def run(self):
        layer = self.ctx.primary
        # shared prefixes keep the number of literal passes over the image small
        anchors = list(PREFIXES)
        anchors16 = [b"".join(bytes([c, 0]) for c in pre) for pre in PREFIXES]
        seen = {}

        def hits():
            for off, m in scan(layer, AnchoredScanner(anchors, ASCII_RE, before=1, after=1100)):
                yield off, m.group(1).decode(), m.group(2).decode("latin-1"), "ascii"
            for off, m in scan(layer, AnchoredScanner(anchors16, UTF16_RE, before=2, after=2200)):
                yield off, m.group(1).decode("utf-16-le"), m.group(2).decode("utf-16-le", "replace"), "utf-16"

        def rows():
            for off, name, value, enc in sorted(hits()):
                key = (name, value)
                seen[key] = seen.get(key, 0) + 1
                if seen[key] > 1 and not self.opts["all"]:
                    continue
                yield 0, (Address(off), enc, name, value, severity(name, value), _SEV[name][1])
        return TreeGrid([("Offset", Address), ("Encoding", str), ("Variable", str), ("Value", str),
                         ("Severity", str), ("Meaning", str)], rows())
