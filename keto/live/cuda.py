"""CUDA driver API through ctypes (``libcuda.so.1`` / ``nvcuda.dll``).

Used by acquisition (allocate device memory, copy it back without
initialising it, to capture residual data) and by the self-test that JIT
compiles a probe kernel to produce real artefacts (a cubin and a live CUDA
process) for validating the live plugins.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Dict, List, Optional

from keto.framework.exceptions import LiveSourceError

ATTR = {"pci_bus": 33, "pci_device": 34, "pci_domain": 50, "cc_major": 75, "cc_minor": 76,
        "integrated": 18, "unified_addressing": 41, "multiprocessors": 16, "memory_bus_width": 37,
        "l2_cache": 38, "tcc_driver": 35, "can_map_host_memory": 19}
JIT_INPUT_PTX = 1


class CudaDriver:
    def __init__(self):
        names = ["nvcuda.dll"] if sys.platform.startswith("win") else ["libcuda.so.1", "/usr/lib/wsl/lib/libcuda.so.1",
                                                                       "libcuda.so"]
        self.lib = None
        last = None
        for n in names:
            try:
                self.lib = ctypes.CDLL(n)
                break
            except OSError as exc:
                last = exc
        if self.lib is None:
            raise LiveSourceError("CUDA driver library not found: %s" % last)
        self.check(self.lib.cuInit(0), "cuInit")
        self.ctx = None

    def error_string(self, rc: int) -> str:
        s = ctypes.c_char_p()
        try:
            self.lib.cuGetErrorString(rc, ctypes.byref(s))
            return (s.value or b"").decode()
        except Exception:
            return "CUDA error %d" % rc

    def check(self, rc: int, what: str):
        if rc != 0:
            raise LiveSourceError("%s failed: %s (%d)" % (what, self.error_string(rc), rc))

    def driver_version(self) -> int:
        v = ctypes.c_int()
        self.check(self.lib.cuDriverGetVersion(ctypes.byref(v)), "cuDriverGetVersion")
        return v.value

    def devices(self) -> List[Dict]:
        n = ctypes.c_int()
        self.check(self.lib.cuDeviceGetCount(ctypes.byref(n)), "cuDeviceGetCount")
        out = []
        for i in range(n.value):
            dev = ctypes.c_int()
            self.check(self.lib.cuDeviceGet(ctypes.byref(dev), i), "cuDeviceGet")
            name = ctypes.create_string_buffer(256)
            self.lib.cuDeviceGetName(name, 256, dev)
            total = ctypes.c_size_t()
            self.lib.cuDeviceTotalMem_v2(ctypes.byref(total), dev)
            attrs = {}
            for k, a in ATTR.items():
                v = ctypes.c_int()
                if self.lib.cuDeviceGetAttribute(ctypes.byref(v), a, dev) == 0:
                    attrs[k] = v.value
            uuid = ctypes.create_string_buffer(16)
            fn = getattr(self.lib, "cuDeviceGetUuid_v2", None) or getattr(self.lib, "cuDeviceGetUuid", None)
            uid = None
            if fn is not None and fn(uuid, dev) == 0:
                b = uuid.raw
                uid = "GPU-%s-%s-%s-%s-%s" % (b[0:4].hex(), b[4:6].hex(), b[6:8].hex(), b[8:10].hex(), b[10:16].hex())
            entry = {"ordinal": i, "name": name.value.decode(), "total_memory": total.value, "uuid": uid,
                     "compute_capability": "%d.%d" % (attrs.get("cc_major", 0), attrs.get("cc_minor", 0)),
                     "pci_bus_id": "%04x:%02x:%02x.0" % (attrs.get("pci_domain", 0), attrs.get("pci_bus", 0),
                                                         attrs.get("pci_device", 0)),
                     "attributes": attrs}
            luid_fn = getattr(self.lib, "cuDeviceGetLuid", None) if sys.platform.startswith("win") else None
            luid, mask = ctypes.create_string_buffer(8), ctypes.c_uint()
            if luid_fn is not None and luid_fn(luid, ctypes.byref(mask), dev) == 0:
                # the adapter LUID the Windows GPU counters and DXGI use (LowPart, then HighPart)
                low, high = int.from_bytes(luid.raw[0:4], "little"), int.from_bytes(luid.raw[4:8], "little")
                entry["luid"] = "0x%08X_0x%08X" % (high, low)
            out.append(entry)
        return out

    # -- context / memory ---------------------------------------------------------
    def create_context(self, ordinal: int = 0):
        dev = ctypes.c_int()
        self.check(self.lib.cuDeviceGet(ctypes.byref(dev), ordinal), "cuDeviceGet")
        ctx = ctypes.c_void_p()
        create = getattr(self.lib, "cuCtxCreate_v2")
        self.check(create(ctypes.byref(ctx), 0, dev), "cuCtxCreate")
        self.ctx = ctx
        return ctx

    def destroy_context(self):
        if self.ctx is not None:
            self.lib.cuCtxDestroy_v2(self.ctx)
            self.ctx = None

    def mem_info(self):
        free, total = ctypes.c_size_t(), ctypes.c_size_t()
        self.check(self.lib.cuMemGetInfo_v2(ctypes.byref(free), ctypes.byref(total)), "cuMemGetInfo")
        return free.value, total.value

    def alloc(self, size: int) -> int:
        ptr = ctypes.c_uint64()
        self.check(self.lib.cuMemAlloc_v2(ctypes.byref(ptr), ctypes.c_size_t(size)), "cuMemAlloc")
        return ptr.value

    def try_alloc(self, size: int) -> Optional[int]:
        ptr = ctypes.c_uint64()
        if self.lib.cuMemAlloc_v2(ctypes.byref(ptr), ctypes.c_size_t(size)) != 0:
            return None
        return ptr.value

    def free(self, ptr: int):
        self.lib.cuMemFree_v2(ctypes.c_uint64(ptr))

    def read(self, ptr: int, size: int) -> bytes:
        buf = (ctypes.c_char * size)()
        self.check(self.lib.cuMemcpyDtoH_v2(buf, ctypes.c_uint64(ptr), ctypes.c_size_t(size)), "cuMemcpyDtoH")
        return bytes(buf)

    def write(self, ptr: int, data: bytes):
        self.check(self.lib.cuMemcpyHtoD_v2(ctypes.c_uint64(ptr), data, ctypes.c_size_t(len(data))), "cuMemcpyHtoD")

    def memset8(self, ptr: int, value: int, size: int):
        self.check(self.lib.cuMemsetD8_v2(ctypes.c_uint64(ptr), ctypes.c_ubyte(value), ctypes.c_size_t(size)),
                   "cuMemsetD8")
        self.check(self.lib.cuCtxSynchronize(), "cuCtxSynchronize")

    # -- JIT ----------------------------------------------------------------------------
    def jit_ptx(self, ptx: bytes, name: str = "module.ptx") -> bytes:
        """Compile PTX to a cubin with the driver's JIT linker and return the cubin bytes."""
        state = ctypes.c_void_p()
        self.check(self.lib.cuLinkCreate_v2(0, None, None, ctypes.byref(state)), "cuLinkCreate")
        try:
            self.check(self.lib.cuLinkAddData_v2(state, JIT_INPUT_PTX, ptx, ctypes.c_size_t(len(ptx)),
                                                 name.encode(), 0, None, None), "cuLinkAddData")
            cub, size = ctypes.c_void_p(), ctypes.c_size_t()
            self.check(self.lib.cuLinkComplete(state, ctypes.byref(cub), ctypes.byref(size)), "cuLinkComplete")
            return ctypes.string_at(cub, size.value)
        finally:
            self.lib.cuLinkDestroy(state)

    def launch_probe(self, cubin: bytes, kernel: str, arg_ptr: int, threads: int = 32):
        mod = ctypes.c_void_p()
        self.check(self.lib.cuModuleLoadData(ctypes.byref(mod), cubin), "cuModuleLoadData")
        fn = ctypes.c_void_p()
        self.check(self.lib.cuModuleGetFunction(ctypes.byref(fn), mod, kernel.encode()), "cuModuleGetFunction")
        arg = ctypes.c_uint64(arg_ptr)
        params = (ctypes.c_void_p * 1)(ctypes.cast(ctypes.byref(arg), ctypes.c_void_p))
        self.check(self.lib.cuLaunchKernel(fn, 1, 1, 1, threads, 1, 1, 0, None, params, None), "cuLaunchKernel")
        self.check(self.lib.cuCtxSynchronize(), "cuCtxSynchronize")
        return mod


PROBE_PTX = b""".version 7.0
.target sm_52
.address_size 64
.visible .entry keto_probe(.param .u64 p){
 .reg .b64 %rd<3>; .reg .b32 %r<3>;
 ld.param.u64 %rd1, [p];
 cvta.to.global.u64 %rd2, %rd1;
 mov.u32 %r1, %tid.x;
 st.global.u32 [%rd2], %r1;
 ret;
}
"""
