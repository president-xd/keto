"""An in-memory fake Linux system with NVIDIA GPUs, for testing live plugins.

``FakeSystemSource`` implements the full ``LiveSource`` interface from a
scenario dictionary (files, links, stat overrides, processes, NVML/CUDA data,
allow-listed command outputs and process memory). ``default_scenario()``
plants one instance of every condition the live plugins are meant to detect.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import struct
from typing import Any, Dict, List

from keto.formats.cubin import build_cubin
from keto.framework.exceptions import LiveSourceError
from keto.live.source import ALLOWED_COMMANDS, MAX_TEXT, LiveSource, keep_env

NOW = 1794880000.0          # 2026-11-17
BOOT = NOW - 86400.0
S_IFCHR, S_IFREG, S_IFDIR, S_IFLNK = 0o020000, 0o100000, 0o040000, 0o120000


class FakeSystemSource(LiveSource):
    kind = "fake"

    def __init__(self, scenario: Dict[str, Any]):
        s = copy.deepcopy(scenario)
        self.files: Dict[str, bytes] = {k: (v.encode() if isinstance(v, str) else v) for k, v in s["files"].items()}
        self.links: Dict[str, str] = s.get("links", {})
        self.stats: Dict[str, dict] = s.get("stats", {})
        self.extra_dirs = set(s.get("dirs", []))
        self.procs: Dict[int, dict] = {int(k): v for k, v in s.get("procs", {}).items()}
        self._nvml = s.get("nvml", {"available": False, "error": "no NVML", "devices": []})
        self._cuda = s.get("cuda", {"available": False, "error": "no CUDA"})
        self.commands: List[list] = s.get("commands", [])
        self.memory: Dict[int, List[list]] = {int(k): v for k, v in s.get("memory", {}).items()}
        self._platform = s.get("platform", {"system": "Linux", "wsl": False})
        self._now = s.get("now", NOW)
        self.mtimes: Dict[str, float] = s.get("mtimes", {})
        self.registry_values: Dict[str, Any] = s.get("registry", {})
        self.win: Dict[str, Any] = s.get("windows", {})

    # -- filesystem -----------------------------------------------------------------
    def _all_paths(self):
        return list(self.files) + list(self.links) + list(self.stats) + list(self.extra_dirs)

    def _is_dir(self, path):
        path = path.rstrip("/") or "/"
        if path in self.extra_dirs:
            return True
        prefix = path + "/" if path != "/" else "/"
        return any(p.startswith(prefix) for p in self._all_paths())

    def read_bytes(self, path, limit=MAX_TEXT):
        data = self.files.get(path)
        if data is None and path in self.links:
            target = self.links[path]
            if not target.startswith("/"):
                target = os.path.join(os.path.dirname(path), target).replace("\\", "/")
            data = self.files.get(target)
        return None if data is None else data[:limit]

    def read_text(self, path, limit=MAX_TEXT):
        data = self.read_bytes(path, limit)
        return None if data is None else data.decode("utf-8", "replace")

    def listdir(self, path):
        path = path.rstrip("/") or "/"
        if not self._is_dir(path):
            return None
        prefix = path + "/" if path != "/" else "/"
        names = set()
        for p in self._all_paths():
            if p.startswith(prefix):
                names.add(p[len(prefix):].split("/", 1)[0])
        return sorted(n for n in names if n)

    def readlink(self, path):
        return self.links.get(path)

    def stat(self, path):
        if path in self.stats:
            d = dict(self.stats[path])
        elif path in self.links:
            d = {"mode": S_IFLNK | 0o777, "uid": 0, "gid": 0, "size": len(self.links[path])}
        elif path in self.files:
            d = {"mode": S_IFREG | 0o644, "uid": 0, "gid": 0, "size": len(self.files[path])}
        elif self._is_dir(path):
            d = {"mode": S_IFDIR | 0o755, "uid": 0, "gid": 0, "size": 4096}
        else:
            return None
        mode = d["mode"]
        mt = self.mtimes.get(path, BOOT)
        d.setdefault("mtime", mt)
        d.setdefault("ctime", mt)
        d.setdefault("atime", mt)
        d.update(perm=oct(mode & 0o7777), is_dir=(mode & 0o170000) == S_IFDIR, is_link=(mode & 0o170000) == S_IFLNK,
                 is_char=(mode & 0o170000) == S_IFCHR, is_reg=(mode & 0o170000) == S_IFREG)
        return d

    def file_sha256(self, path):
        data = self.read_bytes(path, 1 << 40)
        return hashlib.sha256(data).hexdigest() if data is not None else None

    def registry(self, key, name):
        return self.registry_values.get("%s\\%s" % (key, name))

    def win_processes(self):
        return self.win.get("processes", [])

    def win_modules(self, pid):
        return self.win.get("modules", {}).get(str(pid))

    def win_windowed(self):
        return self.win.get("windowed", [])

    def win_gpu(self):
        return self.win.get("gpu", {"available": False, "processes": {}})

    # -- processes -------------------------------------------------------------------
    def pids(self):
        return sorted(self.procs)

    def proc(self, pid):
        p = self.procs.get(pid)
        if p is None:
            return None
        p = copy.deepcopy(p)
        if p.get("environ") is not None:
            p["environ_total"] = len(p["environ"])
            p["environ"] = {k: v for k, v in p["environ"].items() if keep_env(k)}
        return p

    def proc_mem(self, pid, address, length):
        for start, data in self.memory.get(pid, []):
            if start <= address and address + length <= start + len(data):
                return data[address - start:address - start + length]
        return None

    # -- other -----------------------------------------------------------------------
    def platform(self):
        return dict(self._platform)

    def nvml(self):
        return copy.deepcopy(self._nvml)

    def cuda(self):
        return copy.deepcopy(self._cuda)

    def command(self, argv, timeout=30):
        if not argv or os.path.basename(argv[0]) not in ALLOWED_COMMANDS:
            raise LiveSourceError("command %r is not on the read-only allow list" % (argv[:1],))
        for cargv, result in self.commands:
            if list(cargv) == list(argv):
                return dict(result)
        return {"rc": None, "stdout": "", "stderr": "[Errno 2] No such file or directory: %r" % argv[0]}

    def now(self):
        return self._now


# ----------------------------------------------------------------------------------------
# scenario helpers
# ----------------------------------------------------------------------------------------
def build_shared_object(funcs: Dict[str, int], text_size: int = 0x1000) -> bytes:
    """A tiny x86-64 ELF shared object: one r-x PT_LOAD covering the file, a .text
    section at file offset 0x1000 and a .dynsym naming ``funcs`` (name -> .text offset)."""
    text_off = 0x1000
    text = bytes((0x55 + i) & 0xFF for i in range(text_size))
    dynstr = b"\x00"
    syms = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    for name, off in funcs.items():
        name_off = len(dynstr)
        dynstr += name.encode() + b"\x00"
        syms.append(struct.pack("<IBBHQQ", name_off, (1 << 4) | 2, 0, 4, text_off + off, 0x40))
    dynsym = b"".join(syms)
    shstr = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.text\x00"
    body = bytearray(text_off)
    body += text
    dynstr_off = len(body)
    body += dynstr
    while len(body) % 8:
        body += b"\x00"
    dynsym_off = len(body)
    body += dynsym
    shstr_off = len(body)
    body += shstr
    while len(body) % 8:
        body += b"\x00"
    shoff = len(body)
    shdrs = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
             struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
             struct.pack("<IIQQQQIIQQ", 11, 3, 2, dynstr_off, dynstr_off, len(dynstr), 0, 0, 1, 0),
             struct.pack("<IIQQQQIIQQ", 19, 11, 2, dynsym_off, dynsym_off, len(dynsym), 2, 1, 8, 24),
             struct.pack("<IIQQQQIIQQ", 27, 1, 6, text_off, text_off, text_size, 0, 0, 16, 0)]
    body += b"".join(shdrs)
    file_size = len(body)
    hdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    hdr += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, shoff, 0, 64, 56, 1, 64, len(shdrs), 1)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, file_size, file_size, 0x1000)
    body[0:64] = hdr
    body[64:64 + len(ph)] = ph
    return bytes(body)


def _maps(*entries):
    out = []
    for start, end, perms, offset, path in entries:
        out.append({"start": start, "end": end, "perms": perms, "offset": offset, "dev": "08:01",
                    "inode": 0 if not path or path.startswith("[") else 1000 + len(out), "path": path})
    return out


def _proc(pid, ppid, comm, exe, cmdline, uid=1000, maps=(), fds=(), environ=None, cgroup="0::/user.slice",
          start=NOW - 3600, tracer=0):
    return {"pid": pid, "comm": comm, "cmdline": list(cmdline), "exe": exe, "cwd": "/",
            "status": {"Name": comm, "State": "S (sleeping)", "PPid": str(ppid), "Uid": "%d %d %d %d" % ((uid,) * 4),
                       "TracerPid": str(tracer)},
            "ppid": ppid, "uid": uid, "tracer_pid": tracer, "start_time": start,
            "environ": dict(environ) if environ is not None else None, "environ_total": None,
            "maps": list(maps), "fds": [list(f) for f in fds], "cgroup": cgroup}


LIBDIR = "/usr/lib/x86_64-linux-gnu"
LIBCUDA = LIBDIR + "/libcuda.so.565.57.01"
LIBML = LIBDIR + "/libnvidia-ml.so.565.57.01"
CUDA_BASE = 0x7F0000000000
NVFDS = [[3, "/dev/nvidiactl"], [4, "/dev/nvidia0"], [5, "/dev/nvidia-uvm"]]


def _cuda_maps(lib_size):
    return [(CUDA_BASE, CUDA_BASE + 0x1000, "r--p", 0, LIBCUDA),
            (CUDA_BASE + 0x1000, CUDA_BASE + ((lib_size + 0xFFF) & ~0xFFF), "r-xp", 0x1000, LIBCUDA)]


def default_scenario() -> Dict[str, Any]:
    libcuda = build_shared_object({"cuInit": 0x0, "cuLaunchKernel": 0x200, "cuMemAlloc_v2": 0x400})
    hooked = bytearray(libcuda)
    hooked[0x1200:0x1205] = b"\xe9\x10\x20\x30\x40"   # JMP rel32 over cuLaunchKernel's first bytes
    cuda_maps = _cuda_maps(len(libcuda))
    ml_map = (0x7F1000000000, 0x7F1000100000, "r-xp", 0, LIBML)
    cache_cubin = build_cubin({"train_step": b"\x00" * 16 * 8})
    cache_ptx = b"//\n.version 8.5\n.target sm_89\n.address_size 64\n.visible .entry kawpow_hash(\n)\n{\n ret;\n}\n"
    files = {
        "/proc/stat": "cpu 0 0 0 0\nbtime %d\n" % int(BOOT),
        "/proc/driver/nvidia/version": "NVRM version: NVIDIA UNIX x86_64 Kernel Module  565.57.01  Thu Oct 10 "
                                       "12:29:05 UTC 2024\nGCC version:  gcc version 12.3.0\n",
        "/proc/driver/nvidia/gpus/0000:01:00.0/information":
            "Model: \t\t NVIDIA GeForce RTX 4090\nIRQ:   \t\t 160\nGPU UUID: \t GPU-11111111-2222-3333-4444-555555555555\n"
            "Video BIOS: \t 95.02.18.80.5f\nBus Type: \t PCIe\nBus Location: \t 0000:01:00.0\nDevice Minor: \t 0\n"
            "GPU Firmware: \t 565.57.01\nGPU Excluded:\t No\n",
        "/proc/driver/nvidia/params": "ResmanDebugLevel: 4294967295\nModifyDeviceFiles: 1\nDeviceFileUID: 0\n"
                                      "DeviceFileGID: 0\nDeviceFileMode: 438\nInitializeSystemMemoryAllocations: 1\n"
                                      "RmProfilingAdminOnly: 0\nEnableGpuFirmware: 18\nRegistryDwords: \"\"\n",
        "/proc/modules": ("nvidia_uvm 4911104 4 - Live 0x0000000000000000 (PO)\n"
                          "nvidia_drm 122880 2 - Live 0x0000000000000000 (PO)\n"
                          "nvidia_modeset 1355776 3 nvidia_drm, Live 0x0000000000000000 (PO)\n"
                          "nvidia 54591488 120 nvidia_uvm,nvidia_modeset,gpu_snoop, Live 0x0000000000000000 (PO)\n"
                          "gpu_snoop 16384 0 - Live 0x0000000000000000 (OE)\n"
                          "ext4 1015808 1 - Live 0x0000000000000000\n"),
        "/sys/module/nvidia/version": "565.57.01\n", "/sys/module/nvidia/srcversion": "A1B2C3D4E5F60718293A4B5\n",
        "/sys/module/nvidia/taint": "PO\n", "/sys/module/nvidia_uvm/version": "565.57.01\n",
        "/sys/module/nvidia_uvm/taint": "PO\n", "/sys/module/nvidia_modeset/version": "565.57.01\n",
        "/sys/module/nvidia_drm/version": "565.57.01\n", "/sys/module/gpu_snoop/taint": "OE\n",
        "/sys/bus/pci/devices/0000:01:00.0/vendor": "0x10de\n", "/sys/bus/pci/devices/0000:01:00.0/device": "0x2684\n",
        "/sys/bus/pci/devices/0000:01:00.0/class": "0x030000\n", "/sys/bus/pci/devices/0000:01:00.0/numa_node": "-1\n",
        "/sys/bus/pci/devices/0000:01:00.0/current_link_speed": "16.0 GT/s PCIe\n",
        "/sys/bus/pci/devices/0000:01:00.0/current_link_width": "16\n",
        "/sys/bus/pci/devices/0000:01:00.0/max_link_speed": "16.0 GT/s PCIe\n",
        "/sys/bus/pci/devices/0000:01:00.1/vendor": "0x10de\n", "/sys/bus/pci/devices/0000:01:00.1/device": "0x22ba\n",
        "/sys/bus/pci/devices/0000:01:00.1/class": "0x040300\n",
        "/sys/bus/pci/devices/0000:00:1f.0/vendor": "0x8086\n",
        "/lib/firmware/nvidia/565.57.01/gsp_ga10x.bin": b"GSP-FIRMWARE-ga10x" * 64,
        "/lib/firmware/nvidia/565.57.01/gsp_tu10x.bin": b"GSP-FIRMWARE-tu10x" * 64,
        "/etc/modprobe.d/nvidia.conf": "options nvidia NVreg_RestrictProfilingToAdminUsers=0 "
                                       "NVreg_PreserveVideoMemoryAllocations=1\n",
        "/etc/modprobe.d/blacklist.conf": "blacklist pcspkr\n",
        "/etc/OpenCL/vendors/nvidia.icd": "libnvidia-opencl.so.1\n",
        "/etc/OpenCL/vendors/zz-hook.icd": "/tmp/.cache/libOpenCL-hook.so\n",
        "/usr/share/vulkan/icd.d/nvidia_icd.json": json.dumps({"file_format_version": "1.0.0", "ICD": {
            "library_path": "libGLX_nvidia.so.0", "api_version": "1.3.289"}}),
        "/usr/share/vulkan/implicit_layer.d/nvidia_layers.json": json.dumps({"file_format_version": "1.0.0", "layer": {
            "name": "VK_LAYER_NV_optimus", "type": "INSTANCE", "library_path": "libGLX_nvidia.so.0"}}),
        "/etc/vulkan/implicit_layer.d/VkLayer_capture.json": json.dumps({"file_format_version": "1.0.0", "layer": {
            "name": "VK_LAYER_capture", "type": "GLOBAL", "library_path": "/tmp/.vk/libVkLayer_capture.so"}}),
        "/usr/share/glvnd/egl_vendor.d/10_nvidia.json": json.dumps({"file_format_version": "1.0.0", "ICD": {
            "library_path": "libEGL_nvidia.so.0"}}),
        "/etc/ld.so.preload": "/usr/local/lib/libgpuhook.so\n",
        "/etc/udev/rules.d/70-nvidia.rules": 'KERNEL=="nvidia*", RUN+="/usr/bin/nvidia-modprobe -c0 -u"\n',
        "/lib/systemd/system/nvidia-persistenced.service": "[Service]\nExecStart=/usr/bin/nvidia-persistenced "
                                                           "--user nvidia-persistenced\n",
        "/usr/bin/nvidia-persistenced": b"\x7fELF-persistenced",
        "/usr/bin/nvidia-smi": b"\x7fELF-nvidia-smi-modified",
        "/usr/bin/nv-hostengine": b"\x7fELF-hostengine",
        LIBCUDA: libcuda,
        LIBML: b"\x7fELF-libnvidia-ml",
        "/home/alice/.nv/ComputeCache/index": b"\x00" * 64,
        "/home/alice/.nv/ComputeCache/3/a/5c1e0f": b"CACHEHDR" + cache_cubin,
        "/home/alice/.nv/ComputeCache/7/2/99ab01": b"CACHEHDR" + cache_ptx,
        "/home/alice/.cache/nvidia/GLCache/0ab1/shader.bin": b"\x01\x02\x03\x04" * 16,
        "/proc/driver/nvidia/capabilities/gpu1/mig/gi1/access": "DeviceFileMinor: 21\nDeviceFileMode: 292\n",
        "/proc/driver/nvidia/capabilities/gpu1/mig/gi1/ci0/access": "DeviceFileMinor: 22\nDeviceFileMode: 292\n",
    }
    links = {
        LIBDIR + "/libcuda.so.1": "libcuda.so.565.57.01",
        LIBDIR + "/libnvidia-ml.so.1": "libnvidia-ml.so.565.57.01",
        "/sys/bus/pci/devices/0000:01:00.0/driver": "../../../bus/pci/drivers/nvidia",
        "/sys/bus/pci/devices/0000:01:00.0/iommu_group": "../../../kernel/iommu_groups/14",
        "/sys/bus/pci/devices/0000:01:00.1/driver": "../../../bus/pci/drivers/snd_hda_intel",
    }
    chr_ = lambda maj, mnr, mode=0o666: {"mode": S_IFCHR | mode, "uid": 0, "gid": 0, "size": 0,
                                        "rdev_major": maj, "rdev_minor": mnr}
    stats = {
        "/dev/nvidiactl": chr_(195, 255), "/dev/nvidia0": chr_(195, 0), "/dev/nvidia-modeset": chr_(195, 254),
        "/dev/nvidia-uvm": chr_(508, 0), "/dev/nvidia-uvm-tools": chr_(508, 1),
        "/dev/nvidia-caps/nvidia-cap1": chr_(511, 1, 0o400), "/dev/nvidia-caps/nvidia-cap2": chr_(511, 2, 0o666),
        "/dev/nvidia1": {"mode": S_IFREG | 0o666, "uid": 1001, "gid": 1001, "size": 0},
    }
    mtimes = {"/home/alice/.nv/ComputeCache/3/a/5c1e0f": NOW - 7200, "/home/alice/.nv/ComputeCache/7/2/99ab01": NOW - 600,
              "/home/alice/.cache/nvidia/GLCache/0ab1/shader.bin": NOW - 86000}
    dirs = ["/root", "/home/bob", "/dev/nvidia-caps"]
    procs = {
        1: _proc(1, 0, "systemd", "/usr/lib/systemd/systemd", ["/sbin/init"], uid=0, start=BOOT + 1),
        900: _proc(900, 1, "nvidia-persiste", "/usr/bin/nvidia-persistenced",
                   ["/usr/bin/nvidia-persistenced", "--user", "nvidia-persistenced"], uid=0,
                   maps=_maps((0x7F2000000000, 0x7F2000010000, "r-xp", 0, LIBDIR + "/libnvidia-cfg.so.565.57.01")),
                   fds=[[3, "/dev/nvidiactl"], [4, "/dev/nvidia0"]], start=BOOT + 5),
        901: _proc(901, 1, "nv-hostengine", "/usr/bin/nv-hostengine", ["/usr/bin/nv-hostengine", "-n"], uid=0,
                   maps=_maps(ml_map), fds=[[3, "/dev/nvidiactl"], [4, "/dev/nvidia0"]], start=BOOT + 6),
        1000: _proc(1000, 1, "bash", "/usr/bin/bash", ["-bash"], start=NOW - 7000),
        1200: _proc(1200, 1000, "python3", "/usr/bin/python3.10", ["python3", "train.py", "--epochs", "10"],
                    maps=_maps(*(cuda_maps + [(0x7F3000000000, 0x7F3000080000, "r-xp", 0,
                                               "/home/alice/venv/lib/python3.10/site-packages/nvidia/cuda_runtime/lib/"
                                               "libcudart.so.12"),
                                              (0x200000000, 0x200200000, "rw-s", 0, "/dev/zero (deleted)"),
                                              (0x7F3100000000, 0x7F3100001000, "rw-s", 0, "/memfd:wayland-shm (deleted)")])),
                    fds=NVFDS, environ={"CUDA_VISIBLE_DEVICES": "0", "HOME": "/home/alice", "SECRET_TOKEN": "x"}),
        1300: _proc(1300, 1, "xmrig", "/opt/miner/xmrig",
                    ["./xmrig", "-o", "stratum+tcp://pool.supportxmr.com:3333", "--cuda"], uid=1001,
                    maps=_maps(*(cuda_maps + [(0x7F4000000000, 0x7F4000040000, "r-xp", 0,
                                               "/opt/miner/libxmrig-cuda.so")])), fds=NVFDS, environ={}),
        1400: _proc(1400, 1, "kworker/0:1", "/dev/shm/.k (deleted)", ["[kworker/0:1]"], uid=1001,
                    maps=_maps(*(cuda_maps + [(0x7F5000000000, 0x7F5000010000, "r-xp", 0,
                                               "/dev/shm/libprocesshider.so")])), fds=NVFDS,
                    environ={"LD_PRELOAD": "/dev/shm/libprocesshider.so"}),
        1500: _proc(1500, 1000, "python3", "/usr/bin/python3.10", ["python3", "infer.py"],
                    maps=_maps(*(cuda_maps + [(0x7F6000000000, 0x7F6000010000, "r-xp", 0, "/tmp/libinject.so"),
                                              (0x7F6100000000, 0x7F6100100000, "r-xp", 0,
                                               "/usr/local/cuda/extras/CUPTI/lib64/libcupti.so.12")])),
                    fds=NVFDS + [[6, "/dev/nvidia-uvm-tools"]],
                    environ={"CUDA_INJECTION64_PATH": "/tmp/libinject.so", "NVTX_INJECTION64_PATH": "/tmp/libinject.so"}),
        1600: _proc(1600, 1601, "vectorAdd", "/home/alice/samples/vectorAdd", ["./vectorAdd"], tracer=1601,
                    maps=_maps(*(cuda_maps + [(0x7F7000000000, 0x7F7000100000, "r-xp", 0,
                                               LIBDIR + "/libcudadebugger.so.565.57.01")])), fds=NVFDS),
        1601: _proc(1601, 1000, "cuda-gdb", "/usr/local/cuda/bin/cuda-gdb", ["cuda-gdb", "./vectorAdd"]),
        1700: _proc(1700, 1, "svchostd", "/usr/local/bin/svchostd", ["/usr/local/bin/svchostd"],
                    maps=_maps((0x7F8000000000, 0x7F8000010000, "r-xp", 0, LIBDIR + "/libnvidia-fbc.so.565.57.01"),
                               (0x7F8100000000, 0x7F8100010000, "r-xp", 0, LIBDIR + "/libnvidia-encode.so.565.57.01")),
                    fds=[[3, "/dev/nvidiactl"], [4, "/dev/nvidia0"], [5, "/dev/nvidia-modeset"]]),
        1800: _proc(1800, 1000, "gpu_probe", "/home/bob/gpu_probe", ["./gpu_probe"], uid=1002,
                    fds=[[3, "/dev/nvidiactl"], [4, "/dev/nvidia0"]]),
        1900: _proc(1900, 1, "python3", "/usr/bin/python3.11", ["python3", "serve.py"],
                    maps=_maps(*cuda_maps), fds=NVFDS, environ={"NVIDIA_VISIBLE_DEVICES": "all"},
                    cgroup="0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"),
        2200: _proc(2200, 1, "nvidia-persiste", "/home/bob/.local/bin/nvidia-persistenced",
                    ["nvidia-persistenced"], uid=1002, maps=_maps(*cuda_maps), fds=NVFDS),
    }
    memory = {1200: [[CUDA_BASE, bytes(libcuda[:0x1000])], [CUDA_BASE + 0x1000, bytes(hooked[0x1000:])]]}
    for pid in (1300, 1400, 1500, 1600, 1900, 2200):
        memory[pid] = [[CUDA_BASE, bytes(libcuda[:0x1000])], [CUDA_BASE + 0x1000, bytes(libcuda[0x1000:])]]
    na_ = lambda r: {"_na": r}
    dev0 = {
        "index": 0, "name": "NVIDIA GeForce RTX 4090", "uuid": "GPU-11111111-2222-3333-4444-555555555555",
        "serial": na_("Not Supported"), "board_part_number": na_("Not Supported"), "vbios_version": "95.02.18.80.5F",
        "inforom_image": "G002.0000.00.03", "minor_number": 0, "architecture": {"id": 8, "name": "Ada"},
        "brand": "GeForce", "compute_capability": "8.9",
        "pci": {"bus_id": "00000000:01:00.0", "domain": 0, "bus": 1, "device": 0, "device_id": "0x268410de",
                "subsystem_id": "0x167c1043"},
        "memory": {"total": 25757220864, "free": 20000000000, "used": 5757220864},
        "bar1": {"total": 268435456, "free": 250000000, "used": 18435456},
        "persistence_mode": 1, "display_mode": 1, "display_active": 1, "pstate": 0, "fan_percent": 70,
        "power_mw": 410000, "power_limit_mw": 450000, "accounting_mode": 1, "pcie_gen": 4, "pcie_width": 16,
        "pcie_max_gen": 4, "pcie_max_width": 16, "pcie_replay_counter": 0, "temperature_c": 78,
        "compute_mode": "Default", "driver_model": na_("Not Supported"), "mig_mode": na_("Not Supported"),
        "clocks_mhz": {"graphics": 2520, "sm": 2520, "memory": 10501, "video": 1950},
        "max_clocks_mhz": {"graphics": 3105, "sm": 3105, "memory": 10501, "video": 2415},
        "throttle_reasons": {"mask": 4, "decoded": ["SwPowerCap"]},
        "utilization": {"gpu": 99, "memory": 81},
        "encoder_utilization": {"percent": 12, "sampling_us": 167000},
        "decoder_utilization": {"percent": 0, "sampling_us": 167000},
        "jpg_utilization": na_("Not Supported"), "ofa_utilization": na_("Not Supported"),
        "pcie_tx_kbps": 12000, "pcie_rx_kbps": 340000, "ecc_mode": na_("Not Supported"),
        "ecc_errors": {k: na_("Not Supported") for k in ("volatile_corrected", "volatile_uncorrected",
                                                        "aggregate_corrected", "aggregate_uncorrected")},
        "retired_pages": {"multiple_sbe": na_("Not Supported"), "dbe": na_("Not Supported")},
        "remapped_rows": na_("Not Supported"),
        "compute_processes": [{"pid": 1200, "used_memory": 2147483648, "gpu_instance": None, "compute_instance": None},
                              {"pid": 1300, "used_memory": 1610612736, "gpu_instance": None, "compute_instance": None},
                              {"pid": 1900, "used_memory": 1073741824, "gpu_instance": None, "compute_instance": None}],
        "graphics_processes": [{"pid": 1700, "used_memory": 104857600, "gpu_instance": None, "compute_instance": None},
                               {"pid": 2100, "used_memory": 52428800, "gpu_instance": None, "compute_instance": None}],
        "mps_compute_processes": [],
        "encoder_sessions": [{"session_id": 1, "pid": 1700, "codec": "H264", "resolution": "1920x1080",
                              "avg_fps": 30, "avg_latency_us": 1000}],
        "fbc_sessions": [{"session_id": 7, "pid": 1700, "display": 0, "type": "TOSYS", "flags": 0,
                          "resolution": "1920x1080", "max_resolution": "3840x2160", "avg_fps": 15,
                          "avg_latency_us": 500}],
        "fbc_stats": {"sessions": 1, "avg_fps": 15, "avg_latency_us": 500},
        "encoder_stats": {"sessions": 1, "avg_fps": 30, "avg_latency_us": 1000},
        "accounting": {
            "1200": {"gpu_util": 60, "mem_util": 30, "max_memory": 2147483648, "time_ms": 3600000,
                     "start_time_us": int((NOW - 3600) * 1e6), "running": True},
            "1300": {"gpu_util": 99, "mem_util": 70, "max_memory": 1610612736, "time_ms": 3000000,
                     "start_time_us": int((NOW - 3000) * 1e6), "running": True},
            "2000": {"gpu_util": 97, "mem_util": 50, "max_memory": 3221225472, "time_ms": 7200000,
                     "start_time_us": int((NOW - 90000) * 1e6), "running": False}},
        "process_utilization": [{"pid": 1300, "timestamp_us": int(NOW * 1e6), "sm": 99, "mem": 70, "enc": 0, "dec": 0},
                                {"pid": 1200, "timestamp_us": int(NOW * 1e6), "sm": 41, "mem": 20, "enc": 0, "dec": 0}],
        "nvlink": na_("Not Supported"),
        "p2p": {"1": {"read": "status4", "write": "status4", "nvlink": "status4", "atomics": "status4"}},
    }
    dev1 = copy.deepcopy(dev0)
    dev1.update(index=1, minor_number=1, name="NVIDIA A100-SXM4-40GB", uuid="GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                architecture={"id": 7, "name": "Ampere"}, compute_capability="8.0", brand="Tesla",
                pci={"bus_id": "00000000:41:00.0", "domain": 0, "bus": 0x41, "device": 0,
                     "device_id": "0x20b010de", "subsystem_id": "0x134f10de"},
                ecc_mode={"current": 1, "pending": 1},
                ecc_errors={"volatile_corrected": 3, "volatile_uncorrected": 0, "aggregate_corrected": 12,
                            "aggregate_uncorrected": 1},
                retired_pages={"multiple_sbe": [], "dbe": [0x12340000]},
                remapped_rows={"correctable": 0, "uncorrectable": 1, "pending": 0, "failure": 0},
                mig_mode={"current": 1, "pending": 1}, compute_processes=[], graphics_processes=[],
                encoder_sessions=[], fbc_sessions=[], accounting={}, process_utilization=[],
                utilization={"gpu": 0, "memory": 0},
                nvlink=[{"link": 0, "active": True, "version": 3, "remote_bus_id": "00000000:C1:00.0"},
                        {"link": 1, "active": False}],
                p2p={"0": {"read": "status4", "write": "status4", "nvlink": "status4", "atomics": "status4"}})
    nvml = {"available": True, "library": "libnvidia-ml.so.1", "driver_version": "565.57.01",
            "nvml_version": "12.565.57.01", "cuda_driver_version": "12.7", "devices": [dev0, dev1]}
    cuda = {"available": True, "driver_version": 12070,
            "devices": [{"ordinal": 0, "name": "NVIDIA GeForce RTX 4090", "total_memory": 25757220864,
                         "uuid": dev0["uuid"], "compute_capability": "8.9", "pci_bus_id": "0000:01:00.0",
                         "attributes": {}}]}
    kmsg = ("[ 3600.123456] NVRM: loading NVIDIA UNIX x86_64 Kernel Module  565.57.01\n"
            "[ 7200.500000] NVRM: Xid (PCI:0000:01:00): 31, pid=1400, name=kworker/0:1, Ch 00000010, intr 10000000. "
            "MMU Fault: ENGINE GRAPHICS GPCCLIENT_T1_0 faulted @ 0x7f12_34560000. Fault is of type FAULT_PDE "
            "ACCESS_TYPE_VIRT_READ\n"
            "[ 7300.000000] NVRM: Xid (PCI:0000:01:00): 13, pid=1400, name=kworker/0:1, Graphics Exception: "
            "ESR 0x405840=0x80000000\n"
            "[80000.250000] NVRM: Xid (PCI:0000:41:00): 79, pid='<unknown>', name=<unknown>, GPU has fallen off the bus.\n")
    dpkg_list = "nvidia-utils-565 565.57.01-0ubuntu1\nlibnvidia-compute-565 565.57.01-0ubuntu1\n" \
                "nvidia-container-toolkit 1.16.1-1\nbash 5.1-6ubuntu1\n"
    commands = [
        [["dmesg"], {"rc": 0, "stdout": kmsg, "stderr": ""}],
        [["journalctl", "-k", "-o", "short-iso", "--no-pager"], {"rc": 1, "stdout": "", "stderr": "No journal files"}],
        [["dpkg-query", "-W", "-f=${Package} ${Version}\n"], {"rc": 0, "stdout": dpkg_list, "stderr": ""}],
        [["dpkg-query", "-W", "-f=${Version}", "nvidia-container-toolkit"], {"rc": 0, "stdout": "1.16.1-1", "stderr": ""}],
        [["dpkg", "--verify", "nvidia-utils-565", "libnvidia-compute-565", "nvidia-container-toolkit"],
         {"rc": 1, "stdout": "??5??????   /usr/bin/nvidia-smi\n", "stderr": ""}],
    ]
    return {"platform": {"system": "Linux", "release": "6.8.0-fake", "version": "#1 SMP", "machine": "x86_64",
                         "python": "3.10.12", "hostname": "gpu-lab", "wsl": False,
                         "proc_version": "Linux version 6.8.0-fake"},
            "now": NOW, "files": files, "links": links, "stats": stats, "mtimes": mtimes, "dirs": dirs,
            "procs": {str(k): v for k, v in procs.items()}, "memory": {str(k): v for k, v in memory.items()},
            "nvml": nvml, "cuda": cuda, "commands": commands}


def bugreport_text() -> str:
    return ("____________________________________________\n\nStart of NVIDIA bug report log file.  Mon Nov 16 "
            "10:00:00 UTC 2026\nnvidia-bug-report.sh Version: 34567890\nuname: Linux gpu-lab 6.8.0-fake #1 SMP "
            "x86_64 GNU/Linux\n\n*** /proc/driver/nvidia/version\nNVRM version: NVIDIA UNIX x86_64 Kernel Module  "
            "565.57.01  Thu Oct 10 12:29:05 UTC 2024\n\n*** nvidia-smi --query\n==============NVSMI LOG==============\n"
            "Driver Version                            : 565.57.01\nCUDA Version                              : 12.7\n"
            "Attached GPUs                             : 1\nGPU 00000000:01:00.0\n    Product Name                  : "
            "NVIDIA GeForce RTX 4090\n    GPU UUID                      : GPU-11111111-2222-3333-4444-555555555555\n"
            "    VBIOS Version                 : 95.02.18.80.5F\n\n*** dmesg\n"
            "[ 7200.500000] NVRM: Xid (PCI:0000:01:00): 31, pid=1400, name=kworker/0:1, Ch 00000010, intr 10000000. "
            "MMU Fault: ENGINE GRAPHICS GPCCLIENT_T1_0 faulted @ 0x7f12_34560000. Fault is of type FAULT_PDE "
            "ACCESS_TYPE_VIRT_READ\n")


def write_bugreport(path: str, compress: bool = True) -> str:
    data = bugreport_text().encode()
    with (gzip.open(path, "wb") if compress else open(path, "wb")) as fh:
        fh.write(data)
    return path
