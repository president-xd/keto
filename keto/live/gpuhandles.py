"""Which open handles of a Windows process are GPU evidence (platform-independent, so snapshots of a Windows system
can be classified and tested anywhere).

On Windows a GPU process reaches the GPU through system calls into dxgkrnl (D3DKMT*), not through a device file, so
the GPU evidence among its handles is the device objects some components open (\\Device\\DxgKrnl, NVIDIA's admin
device) and the GPU files it holds open: the CUDA driver's kernel archive (nvcubins.bin, opened at cuInit), shader
and JIT caches in use, NVIDIA capture components.
"""

from __future__ import annotations

import re
from typing import Optional

GPU_HANDLE_KINDS = [
    (re.compile(r"^\\Device\\DxgKrnl", re.I), "DirectX graphics kernel device (D3DKMT)"),
    (re.compile(r"^\\Device\\(?:NvAdminDevice|NvXDCore|nvlddmkm|NvGpu|NVIDIA)", re.I), "NVIDIA driver control device"),
    (re.compile(r"\\DriverStore\\FileRepository\\nv[^\\]*\\nvcubins\.bin$", re.I),
     "CUDA driver kernel archive (opened at cuInit)"),
    (re.compile(r"\\NVIDIA\\ComputeCache\\", re.I), "CUDA JIT ComputeCache in use"),
    (re.compile(r"\\NVIDIA\\DXCache\\", re.I), "NVIDIA DirectX shader cache in use"),
    (re.compile(r"\\NVIDIA\\GLCache\\", re.I), "NVIDIA OpenGL/Vulkan shader cache in use"),
    (re.compile(r"\\D3DSCache\\", re.I), "Direct3D shader cache in use"),
    (re.compile(r"\\NVIDIA Corporation\\(?:ShadowPlay|NvCamera)\\|\\NvFBC|\\CaptureCore", re.I),
     "NVIDIA capture component (screen/GPU capture)"),
    (re.compile(r"\\DriverStore\\FileRepository\\nv[^\\]*\\", re.I), "NVIDIA driver file"),
]


def handle_kind(name: str) -> Optional[str]:
    """What a handle's object name says about GPU use (None: not GPU-related)."""
    for rx, kind in GPU_HANDLE_KINDS:
        if rx.search(name or ""):
            return kind
    return None
